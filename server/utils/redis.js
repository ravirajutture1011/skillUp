
import Redis from "ioredis";

const redis = new Redis("rediss://default:AWcsAAIjcDEzYmQ0YTgzNGI4MWY0YmUxYTBmYzg5Mzk0M2Y3ZDg0ZnAxMA@joint-puma-26412.upstash.io:6379"); // Use the Upstash URL from your .env

export default redis;

