use crate::spiders::Spider;
use futures::stream::StreamExt;
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicUsize, Arc};
use std::{collections::HashSet, time::Duration};
use tokio::sync::{mpsc, Barrier};
use tokio::time::sleep;

pub struct Crawler {
    delay: Duration,
    crawling_concurrency: usize,
    processing_concurrency: usize,
}

// region:        --- Constructors

impl Crawler {
    pub fn new(
        delay: Duration,
        crawling_concurrency: usize,   // urls numbers
        processing_concurrency: usize, // items numbers
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
        // queue capacity
        let crawling_queue_capacity = self.crawling_concurrency * 400;
        let processing_queue_capacity = self.processing_concurrency * 10;

        // create counters
        let mut visited_urls: HashSet<String> = HashSet::new();
        let active_spiders = Arc::new(AtomicUsize::new(0));

        // create channels
        let (urls_to_visit_tx, urls_to_visit_rx) = mpsc::channel(crawling_queue_capacity);
        let (items_tx, items_rx) = mpsc::channel(processing_queue_capacity);
        let (new_urls_tx, mut new_urls_rx) = mpsc::channel(crawling_queue_capacity);

        // set a barrier limit
        let barrier = Arc::new(Barrier::new(3));

        // insert the first urls
        for url in spider.start_urls() {
            visited_urls.insert(url.clone());
            let _ = urls_to_visit_tx.send(url).await;
        }

        // send outputs to processing
        self.launch_processors(spider.clone(), items_rx, barrier.clone());

        // send urls to visit and queue items & new urls
        self.launch_scrapers(
            spider.clone(),
            urls_to_visit_rx,
            new_urls_tx.clone(),
            items_tx,
            active_spiders.clone(),
            barrier.clone(),
        );

        // control loop
        println!(">> start control loop");
        loop {
            // when receive new urls
            if let Some((visited_url, mut new_urls)) = new_urls_rx.try_recv().ok() {
                visited_urls.insert(visited_url);

                println!(">> news url: {:?}", new_urls.len());
                println!(">> news url_0: {:?}", new_urls[0]);
                println!(">> news url_1: {:?}", new_urls[1]);
                println!(">> news url_2: {:?}", new_urls[2]);
                println!(">> news url_1383: {:?}", new_urls[1383]);
                println!(">> news url_1384: {:?}", new_urls[1384]);
                // break;
                let mut new_urls: Vec<String> = new_urls[0..5].to_vec();
                println!(">> news url: {:?}", new_urls.len());
                let new_urls = vec!["https://www.cvedetails.com/cve/CVE-2024-35996/".to_string()];
                for url in new_urls {
                    if !visited_urls.contains(&url) {
                        visited_urls.insert(url.clone());
                        println!(">> queuing: {:?}", url);
                        let _ = urls_to_visit_tx.send(url).await;
                    } else {
                        println!(">> already visited: {:?}", url);
                    }
                }
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
        println!(">> control loop barrier passed");
    }

    fn launch_processors<T: Send + 'static>(
        &self,
        spider: Arc<dyn Spider<Item = T>>,
        items_rx: mpsc::Receiver<T>,
        barrier: Arc<Barrier>,
    ) {
        let concurrency = self.processing_concurrency;

        println!(">> launch processor");
        tokio::spawn(async move {
            tokio_stream::wrappers::ReceiverStream::new(items_rx)
                .for_each_concurrent(concurrency, |item| async {
                    let _ = spider.process(item).await;
                })
                .await;

            // wait here others barrier before continuing
            barrier.wait().await;
            println!("launch_processor barrier ended");
        });
    }

    fn launch_scrapers<T: Send + 'static>(
        &self,
        spider: Arc<dyn Spider<Item = T>>,
        urls_to_visit: mpsc::Receiver<String>,
        new_urls_tx: mpsc::Sender<(String, Vec<String>)>,
        items_tx: mpsc::Sender<T>,
        active_spiders: Arc<AtomicUsize>,
        barrier: Arc<Barrier>,
    ) {
        let concurrency = self.crawling_concurrency;
        let delay = self.delay;

        println!(">> launch scrapers");
        tokio::spawn(async move {
            tokio_stream::wrappers::ReceiverStream::new(urls_to_visit)
                .for_each_concurrent(concurrency, |queued_url| {
                    let queued_url = queued_url.clone();
                    async {
                        println!(">> increment active spider");
                        active_spiders.fetch_add(1, Ordering::SeqCst);

                        let mut urls = Vec::new();

                        // visit url and get result
                        let res = spider
                            .scrape(queued_url.clone())
                            .await
                            .map_err(|err| {
                                println!(">>{:?}", err);
                                err
                            })
                            .ok();

                        // send items if any
                        if let Some((items, new_urls)) = res {
                            println!(
                                ">> scraper result: items: {:?}, new urls: {:.}",
                                items.len(),
                                new_urls.len()
                            );
                            for item in items {
                                let _ = items_tx.send(item).await;
                            }
                            urls = new_urls;
                        }

                        // send new urls if any
                        let _ = new_urls_tx.send((queued_url, urls)).await;

                        // wait and close active spider
                        sleep(delay).await;
                        println!(">> decrement active spider");
                        active_spiders.fetch_sub(1, Ordering::SeqCst);
                    }
                })
                .await;

            // drop items receiver before waiting for other barrier
            drop(items_tx);
            barrier.wait().await;
            println!(">> launch_scrapper ended");
        });
    }
}
