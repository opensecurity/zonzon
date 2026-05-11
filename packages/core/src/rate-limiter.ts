export interface RateLimiterOptions {
  maxRequests: number;
  windowMs: number;
}

interface IpBucket {
  timestamps: number[];
}

export class RateLimiter {
  private options: RateLimiterOptions;
  private buckets = new Map<string, IpBucket>();
  private gcInterval: NodeJS.Timeout;

  constructor(options: RateLimiterOptions) {
    this.options = options;
    
    this.gcInterval = setInterval(() => this.garbageCollect(), Math.max(options.windowMs * 2, 60000));
    this.gcInterval.unref();
  }

  private garbageCollect(): void {
    const now = Date.now();
    const windowStart = now - this.options.windowMs;

    for (const [ip, bucket] of this.buckets.entries()) {
      const validTimestamps = bucket.timestamps.filter((t) => t >= windowStart);
      if (validTimestamps.length === 0) {
        this.buckets.delete(ip);
      } else {
        bucket.timestamps = validTimestamps;
      }
    }
  }

  public destroy(): void {
    clearInterval(this.gcInterval);
    this.buckets.clear();
  }

  allow(ip: string): boolean {
    const now = Date.now();
    let bucket = this.buckets.get(ip);

    if (!bucket || now - bucket.timestamps[0] > this.options.windowMs) {
      bucket = { timestamps: [now] };
      this.buckets.set(ip, bucket);
      return true;
    }

    const windowStart = now - this.options.windowMs;
    while (bucket.timestamps.length > 0 && bucket.timestamps[0] < windowStart) {
      bucket.timestamps.shift();
    }

    if (bucket.timestamps.length >= this.options.maxRequests) {
      return false;
    }

    bucket.timestamps.push(now);
    return true;
  }

  getRequestCount(ip: string): number {
    const now = Date.now();
    const windowStart = now - this.options.windowMs;
    const bucket = this.buckets.get(ip);

    if (!bucket) return 0;

    return bucket.timestamps.filter((t) => t >= windowStart).length;
  }
}