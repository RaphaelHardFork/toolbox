use futures::stream::StreamExt;
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicUsize, Arc};
use std::{collections::HashSet, time::Duration};
use tokio::sync::{mpsc, Barrier};
use tokio::time::sleep;

use crate::spiders::Spider;

pub struct Crawler {
    delay: Duration,
    crawling_concurrency: usize,
    processing_concurrency: usize,
}

// region:        --- Constructors

impl Crawler {
    pub fn new(
        delay: Duration,
        crawling_concurrency: usize,
        processing_concurrency: usize,
    ) -> Self {
        Self {
            delay,
            crawling_concurrency,
            processing_concurrency,
        }
    }
}

// endregion:     --- Constructors

impl Crawler {
    pub async fn run<T: Send + 'static>(&self, spider: Arc<dyn Spider<Item = T>>) {
        let mut visited_urls: HashSet<String> = HashSet::new();
        let active_spiders = Arc::new(AtomicUsize::new(0));

        // crawling queue capacity
        let (urls_to_visit_tx, urls_to_visit_rx) = mpsc::channel(self.crawling_concurrency * 400);
        // processing queue capacity
        let (items_tx, items_rx) = mpsc::channel(self.processing_concurrency * 10);

        let (new_urls_tx, mut new_urls_rx) = mpsc::channel(self.crawling_concurrency * 400);
        let barrier = Arc::new(Barrier::new(3));

        for url in spider.start_urls() {
            visited_urls.insert(url.clone());
            let _ = urls_to_visit_tx.send(url).await;
        }

        self.launch_processors(
            self.processing_concurrency,
            spider.clone(),
            items_rx,
            barrier.clone(),
        );

        self.launch_scrapers(
            self.crawling_concurrency,
            spider.clone(),
            urls_to_visit_rx,
            new_urls_tx.clone(),
            items_tx,
            active_spiders.clone(),
            self.delay,
            barrier.clone(),
        );

        loop {
            println!(">>loop");
            if let Some((visited_url, new_urls)) = new_urls_rx.try_recv().ok() {
                visited_urls.insert(visited_url);

                println!(">> news url: {:?}", new_urls.len());
                println!(">> news url_0: {:?}", new_urls[0]);
                println!(">> news url_1: {:?}", new_urls[1]);
                println!(">> news url_2: {:?}", new_urls[2]);
                println!(">> news url_1383: {:?}", new_urls[1383]);
                println!(">> news url_1384: {:?}", new_urls[1384]);
                break;
                for url in new_urls {
                    if !visited_urls.contains(&url) {
                        visited_urls.insert(url.clone());
                        println!(">> queuing: {:?}", url);
                        let _ = urls_to_visit_tx.send(url).await;
                    }
                }
                println!(">> visited url: {:?}", visited_urls);
            }

            if new_urls_tx.capacity() == self.crawling_concurrency * 400
                && urls_to_visit_tx.capacity() == self.crawling_concurrency * 400
                && active_spiders.load(Ordering::SeqCst) == 0
            {
                // no more work
                break;
            }

            sleep(Duration::from_millis(5)).await;
        }

        println!(">> crawler: control loop exited");
        drop(urls_to_visit_tx);
        barrier.wait().await;
    }

    fn launch_processors<T: Send + 'static>(
        &self,
        concurrency: usize,
        spider: Arc<dyn Spider<Item = T>>,
        items: mpsc::Receiver<T>,
        barrier: Arc<Barrier>,
    ) {
        tokio::spawn(async move {
            tokio_stream::wrappers::ReceiverStream::new(items)
                .for_each_concurrent(concurrency, |item| async {
                    let _ = spider.process(item).await;
                })
                .await;

            barrier.wait().await;
        });
    }

    fn launch_scrapers<T: Send + 'static>(
        &self,
        concurrency: usize,
        spider: Arc<dyn Spider<Item = T>>,
        urls_to_visit: mpsc::Receiver<String>,
        new_urls_tx: mpsc::Sender<(String, Vec<String>)>,
        items_tx: mpsc::Sender<T>,
        active_spiders: Arc<AtomicUsize>,
        delay: Duration,
        barrier: Arc<Barrier>,
    ) {
        tokio::spawn(async move {
            tokio_stream::wrappers::ReceiverStream::new(urls_to_visit)
                .for_each_concurrent(concurrency, |queued_url| {
                    let queued_url = queued_url.clone();
                    async {
                        active_spiders.fetch_add(1, Ordering::SeqCst);
                        let mut urls = Vec::new();
                        let res = spider
                            .scrape(queued_url.clone())
                            .await
                            .map_err(|err| {
                                println!(">>{:?}", err);
                                err
                            })
                            .ok();

                        if let Some((items, new_urls)) = res {
                            for item in items {
                                let _ = items_tx.send(item).await;
                            }
                            urls = new_urls;
                        }

                        let _ = new_urls_tx.send((queued_url, urls)).await;
                        sleep(delay).await;
                        active_spiders.fetch_sub(1, Ordering::SeqCst);
                    }
                })
                .await;

            drop(items_tx);
            barrier.wait().await;
        });
    }
}
