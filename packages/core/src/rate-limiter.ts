export interface RateLimiterOptions {
  maxRequests: number;
  windowMs: number;
}

interface IpBucket {
  count: number;
  resetTime: number;
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
    for (const [ip, bucket] of this.buckets.entries()) {
      if (now >= bucket.resetTime) {
        this.buckets.delete(ip);
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

    if (!bucket || now >= bucket.resetTime) {
      bucket = { count: 1, resetTime: now + this.options.windowMs };
      this.buckets.set(ip, bucket);
      return true;
    }

    if (bucket.count >= this.options.maxRequests) {
      return false;
    }

    bucket.count++;
    return true;
  }

  getRequestCount(ip: string): number {
    const now = Date.now();
    const bucket = this.buckets.get(ip);

    if (!bucket || now >= bucket.resetTime) {
      return 0;
    }

    return bucket.count;
  }
}