use crate::spiders::Spider;
use futures::stream::StreamExt;
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicUsize, Arc};
use std::{collections::HashSet, time::Duration};
use tokio::sync::{mpsc, Barrier};
use tokio::time::sleep;
use tracing::{error, info, instrument, warn};

pub struct Crawler {
    delay: Duration,
    crawling_concurrency: usize,
    processing_concurrency: usize,
    barrier: Arc<Barrier>,
    active_spiders: Arc<AtomicUsize>,
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
            barrier: Arc::new(Barrier::new(3)),
            active_spiders: Arc::new(AtomicUsize::new(0)),
        }
    }
}

// endregion:     --- Constructors

impl Crawler {
    #[instrument(name = "control_loop", level = "info", skip_all)]
    pub async fn run<T: Send + 'static>(&self, spider: Arc<dyn Spider<Item = T>>) {
        info!("Start run with spider: {}", spider.name());

        // queue capacity
        let crawling_queue_capacity = self.crawling_concurrency * 400;
        let processing_queue_capacity = self.processing_concurrency * 10;

        // create counters
        let mut visited_urls: HashSet<String> = HashSet::new();

        // create channels
        let (urls_to_visit_tx, urls_to_visit_rx) = mpsc::channel(crawling_queue_capacity);
        let (items_tx, items_rx) = mpsc::channel(processing_queue_capacity);
        let (new_urls_tx, mut new_urls_rx) = mpsc::channel(crawling_queue_capacity);

        // insert the first urls
        for url in spider.start_urls() {
            visited_urls.insert(url.clone());
            let _ = urls_to_visit_tx.send(url).await;
        }

        // send outputs to processing
        self.launch_processors(spider.clone(), items_rx);

        // send urls to visit and queue items & new urls
        self.launch_scrapers(
            spider.clone(),
            urls_to_visit_rx,
            new_urls_tx.clone(),
            items_tx,
        );

        // control loop
        info!("Launching");
        loop {
            // when receive new urls
            if let Some((visited_url, mut new_urls)) = new_urls_rx.try_recv().ok() {
                visited_urls.insert(visited_url);

                info!("{} urls arrived", new_urls.len());

                // if new_urls.len() > 5 {
                //     // DEV MODE
                //     new_urls = new_urls[0..5].to_vec();
                // }

                for url in new_urls {
                    if !visited_urls.contains(&url) {
                        visited_urls.insert(url.clone());
                        info!("Queuing: {}", url);
                        let _ = urls_to_visit_tx.send(url).await;
                    } else {
                        warn!("Already visited {:?} (should stop in dev mode)", url);
                        break;
                    }
                }
            }

            if new_urls_tx.capacity() == self.crawling_concurrency * 400
                && urls_to_visit_tx.capacity() == self.crawling_concurrency * 400
                && self.active_spiders.load(Ordering::SeqCst) == 0
            {
                // no more work
                break;
            }

            sleep(Duration::from_millis(5)).await;
        }
        info!("Exited");

        drop(urls_to_visit_tx);
        info!("Waiting barrier");
        self.barrier.wait().await;
        info!("Finalized");
    }

    #[instrument(name = "processors", level = "info", skip_all)]
    fn launch_processors<T: Send + 'static>(
        &self,
        spider: Arc<dyn Spider<Item = T>>,
        items_rx: mpsc::Receiver<T>,
    ) {
        let concurrency = self.processing_concurrency;
        let barrier = self.barrier.clone();

        info!("Launching");

        tokio::spawn(async move {
            tokio_stream::wrappers::ReceiverStream::new(items_rx)
                .for_each_concurrent(concurrency, |item| async {
                    let _ = spider.process(item).await;
                })
                .await;

            // wait here others barrier before continuing
            info!("Waiting barrier");
            barrier.wait().await;
            info!("Finalized");
        });
    }

    #[instrument(name = "scrapers", level = "info", skip_all)]
    fn launch_scrapers<T: Send + 'static>(
        &self,
        spider: Arc<dyn Spider<Item = T>>,
        urls_to_visit: mpsc::Receiver<String>,
        new_urls_tx: mpsc::Sender<(String, Vec<String>)>,
        items_tx: mpsc::Sender<T>,
    ) {
        let concurrency = self.crawling_concurrency;
        let delay = self.delay;
        let barrier = self.barrier.clone();
        let active_spiders = self.active_spiders.clone();

        info!("Launching");
        tokio::spawn(async move {
            tokio_stream::wrappers::ReceiverStream::new(urls_to_visit)
                .for_each_concurrent(concurrency, |queued_url| {
                    let queued_url = queued_url.clone();
                    async {
                        let current = active_spiders.fetch_add(1, Ordering::SeqCst);
                        info!("Active spider ({} active)", current + 1);

                        let mut urls = Vec::new();

                        // visit url and get result
                        let res = spider
                            .scrape(queued_url.clone())
                            .await
                            .map_err(|err| {
                                error!("Reason: {:?}", err);
                                err
                            })
                            .ok();

                        // send items if any
                        if let Some((items, new_urls)) = res {
                            info!(
                                "Found {} items & {} new_urls from {:?}",
                                items.len(),
                                new_urls.len(),
                                queued_url
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
                        let now = active_spiders.fetch_sub(1, Ordering::SeqCst);
                        info!("Desactive spider ({} active)", now - 1);
                    }
                })
                .await;

            // drop items receiver before waiting for other barrier
            drop(items_tx);
            info!("Waiting barrier");
            barrier.wait().await;
            info!("Finalized");
        });
    }
}
