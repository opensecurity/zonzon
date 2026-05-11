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

  constructor(options: RateLimiterOptions) {
    this.options = options;
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