use crate::{
    metrics::PayloadBuilderMetrics, BasicPayloadJobGeneratorConfig, BuildArguments, BuildOutcome,
    Cancelled, PayloadBuilder, PayloadConfig,
};
use reth_node_api::PayloadBuilderAttributes;
use reth_payload_builder::{
    error::PayloadBuilderError, KeepPayloadJobAlive, PayloadJob, PayloadJobGenerator,
};
use reth_primitives::{BlockNumberOrTag, ChainSpec};
use reth_provider::{BlockReaderIdExt, BlockSource, StateProviderFactory};

use reth_tasks::TaskSpawner;
use reth_transaction_pool::TransactionPool;
use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, TryLockError},
    task::{Context, Poll},
};
use tracing::trace;

/// The [`MagicPayloadJobGenerator`] that creates [`BasicPayloadJob`]s.
#[derive(Debug)]
pub struct LumioPayloadJobGenerator<Client, Pool, Tasks, Builder = ()> {
    /// The client that can interact with the chain.
    client: Client,
    /// txpool
    pool: Pool,
    /// How to spawn building tasks
    executor: Tasks,
    /// The configuration for the job generator.
    config: BasicPayloadJobGeneratorConfig,
    /// The chain spec.
    chain_spec: Arc<ChainSpec>,
    /// The type responsible for building payloads.
    ///
    /// See [PayloadBuilder]
    builder: Builder,
}

impl<Client, Pool, Tasks> LumioPayloadJobGenerator<Client, Pool, Tasks> {
    /// Creates a new [MagicPayloadJobGenerator] with the given config.
    pub fn new(
        client: Client,
        pool: Pool,
        executor: Tasks,
        config: BasicPayloadJobGeneratorConfig,
        chain_spec: Arc<ChainSpec>,
    ) -> Self {
        LumioPayloadJobGenerator::with_builder(client, pool, executor, config, chain_spec, ())
    }
}

impl<Client, Pool, Tasks, Builder> LumioPayloadJobGenerator<Client, Pool, Tasks, Builder> {
    /// Creates a new [MagicPayloadJobGenerator] with the given config and custom [PayloadBuilder]
    pub fn with_builder(
        client: Client,
        pool: Pool,
        executor: Tasks,
        config: BasicPayloadJobGeneratorConfig,
        chain_spec: Arc<ChainSpec>,
        builder: Builder,
    ) -> Self {
        Self { client, pool, executor, config, chain_spec, builder }
    }
}

impl<Client, Pool, Tasks, Builder> PayloadJobGenerator
    for LumioPayloadJobGenerator<Client, Pool, Tasks, Builder>
where
    Client: StateProviderFactory + BlockReaderIdExt + Clone + Unpin + 'static,
    Pool: TransactionPool + Unpin + 'static,
    Tasks: TaskSpawner + Clone + Unpin + 'static,
    Builder: PayloadBuilder<Pool, Client> + Unpin + 'static,
    <Builder as PayloadBuilder<Pool, Client>>::Attributes: Unpin + Clone,
    <Builder as PayloadBuilder<Pool, Client>>::BuiltPayload: Unpin + Clone,
{
    type Job = LumioPayloadJob<Client, Pool, Builder>;

    fn new_payload_job(
        &self,
        attributes: <Self::Job as PayloadJob>::PayloadAttributes,
    ) -> Result<Self::Job, PayloadBuilderError> {
        let parent_block = if attributes.parent().is_zero() {
            // use latest block if parent is zero: genesis block
            self.client
                .block_by_number_or_tag(BlockNumberOrTag::Latest)?
                .ok_or_else(|| PayloadBuilderError::MissingParentBlock(attributes.parent()))?
                .seal_slow()
        } else {
            let block = self
                .client
                .find_block_by_hash(attributes.parent(), BlockSource::Any)?
                .ok_or_else(|| PayloadBuilderError::MissingParentBlock(attributes.parent()))?;

            // we already know the hash, so we can seal it
            block.seal(attributes.parent())
        };

        let config = PayloadConfig::new(
            Arc::new(parent_block),
            self.config.extradata.clone(),
            attributes,
            Arc::clone(&self.chain_spec),
        );

        Ok(LumioPayloadJob::spawn(
            config,
            self.client.clone(),
            self.pool.clone(),
            self.executor.clone(),
            Default::default(),
            self.builder.clone(),
        ))
    }
}

type JobResult<R> = Result<R, PayloadBuilderError>;

/// A basic payload job that continuously builds a payload with the best transactions from the pool.
#[derive(Debug)]
pub struct LumioPayloadJob<Client, Pool, Builder>
where
    Builder: PayloadBuilder<Pool, Client>,
{
    config_attr: Builder::Attributes,
    payload: Arc<Mutex<Option<JobResult<Builder::BuiltPayload>>>>,
    _cancel: Cancelled,
}

impl<Client, Pool, Builder> LumioPayloadJob<Client, Pool, Builder>
where
    Client: StateProviderFactory + Clone + Unpin + 'static,
    Pool: TransactionPool + Unpin + 'static,
    Builder: PayloadBuilder<Pool, Client> + Unpin + 'static,
    <Builder as PayloadBuilder<Pool, Client>>::Attributes: Unpin + Clone,
    <Builder as PayloadBuilder<Pool, Client>>::BuiltPayload: Unpin + Clone,
{
    fn spawn<Tasks: TaskSpawner + Clone + 'static>(
        config: PayloadConfig<Builder::Attributes>,
        client: Client,
        pool: Pool,
        executor: Tasks,
        metrics: PayloadBuilderMetrics,
        builder: Builder,
    ) -> Self {
        trace!(target: "payload_builder", "spawn new payload build task");
        let cancel = Cancelled::default();
        let cancel_inner = cancel.clone();
        metrics.inc_initiated_payload_builds();

        let payload = Arc::new(Mutex::new(None));
        let payload_inner = payload.clone();
        let config_attr = config.attributes.clone();
        executor.spawn_blocking(Box::pin(async move {
            let args = BuildArguments {
                client,
                pool,
                cached_reads: Default::default(),
                config,
                cancel: cancel_inner,
                best_payload: None,
            };
            match builder.try_build(args) {
                Ok(BuildOutcome::Cancelled) => todo!(),
                Ok(BuildOutcome::Better { payload, .. }) => {
                    payload_inner.lock().unwrap().replace(Ok(payload));
                }
                Ok(BuildOutcome::Aborted { .. }) => {
                    payload_inner.lock().unwrap().replace(Err(PayloadBuilderError::ChannelClosed));
                }
                Err(err) => {
                    payload_inner.lock().unwrap().replace(Err(err));
                }
            }
        }));
        LumioPayloadJob { payload, config_attr, _cancel: cancel }
    }
}

impl<Client, Pool, Builder> Future for LumioPayloadJob<Client, Pool, Builder>
where
    Client: StateProviderFactory + Clone + Unpin + 'static,
    Pool: TransactionPool + Unpin + 'static,
    Builder: PayloadBuilder<Pool, Client> + Unpin + 'static,
    <Builder as PayloadBuilder<Pool, Client>>::Attributes: Unpin + Clone,
    <Builder as PayloadBuilder<Pool, Client>>::BuiltPayload: Unpin + Clone,
{
    type Output = Result<(), PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl<Client, Pool, Builder> PayloadJob for LumioPayloadJob<Client, Pool, Builder>
where
    Client: StateProviderFactory + Clone + Unpin + 'static,
    Pool: TransactionPool + Unpin + 'static,
    Builder: PayloadBuilder<Pool, Client> + Unpin + 'static,
    <Builder as PayloadBuilder<Pool, Client>>::Attributes: Unpin + Clone,
    <Builder as PayloadBuilder<Pool, Client>>::BuiltPayload: Unpin + Clone,
{
    type PayloadAttributes = Builder::Attributes;
    type ResolvePayloadFuture = ResolveLumioPayload<Self::BuiltPayload>;
    type BuiltPayload = Builder::BuiltPayload;

    fn best_payload(&self) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        loop {
            {
                let payload = self.payload.lock().unwrap();
                if let Some(payload) = payload.as_ref() {
                    return payload.clone();
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    fn payload_attributes(&self) -> Result<Self::PayloadAttributes, PayloadBuilderError> {
        Ok(self.config_attr.clone())
    }

    fn resolve(&mut self) -> (Self::ResolvePayloadFuture, KeepPayloadJobAlive) {
        let payload = self.payload.clone();
        (ResolveLumioPayload { payload }, KeepPayloadJobAlive::Yes)
    }
}

/// A future that resolves to the payload of a [LumioPayloadJob].
pub struct ResolveLumioPayload<Payload: Clone> {
    payload: Arc<Mutex<Option<JobResult<Payload>>>>,
}

impl<Payload> Future for ResolveLumioPayload<Payload>
where
    Payload: Unpin + Clone,
{
    type Output = Result<Payload, PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let payload = match this.payload.try_lock() {
            Ok(payload) => payload,
            Err(TryLockError::Poisoned { .. }) => {
                return Poll::Ready(Err(PayloadBuilderError::ChannelClosed))
            }
            Err(TryLockError::WouldBlock) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if let Some(payload) = payload.as_ref() {
            return Poll::Ready(payload.clone());
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<T: Clone> Debug for ResolveLumioPayload<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolveLumioPayload").finish()
    }
}
