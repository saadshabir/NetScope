use crossbeam_channel::{Receiver, Sender, bounded};

#[derive(Debug)]
pub struct PacketBufPool {
    pool: Receiver<Vec<u8>>,
    returner: Sender<Vec<u8>>,
    initial_capacity: usize,
    max_return_capacity: usize,
}

#[derive(Clone, Debug)]
pub struct PacketBufReturner {
    returner: Sender<Vec<u8>>,
    max_return_capacity: usize,
}

impl PacketBufPool {
    pub fn new(pool_capacity: usize, buf_size: usize) -> Self {
        let capacity = pool_capacity.max(1);
        // Most frames fit in 2 KiB. Grow individual buffers on demand for
        // jumbo frames instead of reserving a full snaplen for every slot.
        let initial_capacity = buf_size.min(2048);
        let max_return_capacity = buf_size.saturating_mul(8).max(buf_size);
        let (tx, rx) = bounded::<Vec<u8>>(capacity);
        for _ in 0..capacity {
            let _ = tx.try_send(Vec::with_capacity(initial_capacity));
        }
        PacketBufPool {
            pool: rx,
            returner: tx,
            initial_capacity,
            max_return_capacity,
        }
    }

    pub fn acquire(&self) -> Vec<u8> {
        match self.pool.try_recv() {
            Ok(mut buf) => {
                buf.clear();
                if buf.capacity() < self.initial_capacity {
                    buf.reserve(self.initial_capacity);
                }
                buf
            }
            Err(_) => Vec::with_capacity(self.initial_capacity),
        }
    }

    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() > self.max_return_capacity {
            return;
        }
        buf.clear();
        let _ = self.returner.try_send(buf);
    }

    pub fn returner(&self) -> PacketBufReturner {
        PacketBufReturner {
            returner: self.returner.clone(),
            max_return_capacity: self.max_return_capacity,
        }
    }
}

impl PacketBufReturner {
    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() > self.max_return_capacity {
            return;
        }
        buf.clear();
        let _ = self.returner.try_send(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_buffers_grow_for_full_capture_frames_and_are_reused() {
        let pool = PacketBufPool::new(1, 65535);
        let mut buf = pool.acquire();
        assert_eq!(buf.capacity(), 2048);
        let data = vec![0xab; 65535];
        buf.extend_from_slice(&data);
        assert_eq!(buf, data);
        let grown_capacity = buf.capacity();
        pool.returner().release(buf);
        let reused = pool.acquire();
        assert!(reused.is_empty());
        assert_eq!(reused.capacity(), grown_capacity);
    }

    #[test]
    fn short_snaplen_and_oversized_returns_remain_bounded() {
        let pool = PacketBufPool::new(1, 64);
        let mut buf = pool.acquire();
        assert_eq!(buf.capacity(), 64);
        buf.resize(1024, 0);
        pool.release(buf);
        assert_eq!(pool.acquire().capacity(), 64);
    }
}
