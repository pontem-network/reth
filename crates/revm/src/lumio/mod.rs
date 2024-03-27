/// Contains the magic block type.
pub mod block;
/// Contains the magic coin mapper.
pub mod coin;
/// CrossVM implementation.
pub mod cross_vm;
/// Epoch.
pub mod epoch;
/// Contains the move executor.
pub mod executor;
/// Containce types mapping between move and evm.
pub mod mapper;
/// Preloader.
pub mod preloader;
/// Contains the magic resource io.
pub mod resource;
/// Contains the magic resource mapping tools.
pub mod resource_map;
/// Contains the state view.
pub mod state_view;
/// State that supports tx rollback in case of cross-vm call revert.
pub mod transition_state;
/// Contains common transaction types.
pub mod tx_type;
/// Contains the magic storage value.
pub mod value;
/// Version holder.
pub mod version;

#[cfg(test)]
mod tests;
/// Contains the magic transaction info.
pub mod tx_info;
