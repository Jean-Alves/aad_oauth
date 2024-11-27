const kCacheLocalStorage = 'localStorage';
const kCacheMemoryStorage = 'memoryStorage';
const kCacheSessionStorage = 'sessionStorage';
const kCacheNone = 'none';

enum CacheLocation {
  localStorage(kCacheLocalStorage),
  memoryStorage(kCacheMemoryStorage),
  sessionStorage(kCacheSessionStorage),
  none(kCacheNone);

  final String value;

  const CacheLocation(this.value);
}
