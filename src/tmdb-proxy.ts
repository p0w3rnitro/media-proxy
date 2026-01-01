/**
 * TMDB API Proxy - Routes TMDB requests through Cloudflare Worker
 * 
 * This proxy handles all TMDB API requests, reducing Vercel Edge invocations.
 * 
 * Routes:
 *   GET /tmdb/search?query=<query>&type=<movie|tv|multi>
 *   GET /tmdb/trending?type=<movie|tv|all>&time=<day|week>
 *   GET /tmdb/details?id=<id>&type=<movie|tv>
 *   GET /tmdb/recommendations?id=<id>&type=<movie|tv>
 *   GET /tmdb/season?id=<id>&season=<number>
 *   GET /tmdb/movies?category=<popular|top_rated|upcoming|now_playing>
 *   GET /tmdb/series?category=<popular|top_rated|on_the_air|airing_today>
 *   GET /tmdb/health
 * 
 * Benefits:
 *   - Cloudflare free tier: 100k requests/day
 *   - Built-in caching at edge
 *   - Lower latency
 *   - Reduced Vercel costs
 */

import { createLogger, type LogLevel } from './logger';

export interface TMDBEnv {
  LOG_LEVEL?: string;
  TMDB_API_KEY?: string;
  ALLOWED_ORIGINS?: string;
}

const TMDB_BASE_URL = 'https://api.themoviedb.org/3';

// Cache durations (in seconds)
const CACHE_DURATIONS = {
  search: 300,        // 5 minutes
  trending: 600,      // 10 minutes
  details: 3600,      // 1 hour
  recommendations: 3600,
  season: 3600,
  movies: 600,
  series: 600,
};

// CORS headers
function corsHeaders(origin?: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

// JSON response helper
function jsonResponse(
  data: object, 
  status: number, 
  origin?: string | null,
  cacheSeconds?: number
): Response {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...corsHeaders(origin),
  };
  
  if (cacheSeconds && cacheSeconds > 0) {
    headers['Cache-Control'] = `public, max-age=${cacheSeconds}, s-maxage=${cacheSeconds}`;
  }
  
  return new Response(JSON.stringify(data), { status, headers });
}

// Fetch from TMDB with error handling
async function fetchTMDB(
  endpoint: string, 
  apiKey: string,
  params: Record<string, string> = {}
): Promise<{ ok: boolean; data?: any; error?: string; status?: number }> {
  const url = new URL(`${TMDB_BASE_URL}${endpoint}`);
  url.searchParams.set('api_key', apiKey);
  url.searchParams.set('language', 'en-US');
  
  for (const [key, value] of Object.entries(params)) {
    if (value) url.searchParams.set(key, value);
  }
  
  try {
    const response = await fetch(url.toString());
    
    if (!response.ok) {
      return { 
        ok: false, 
        error: `TMDB API error: ${response.status}`,
        status: response.status 
      };
    }
    
    const data = await response.json();
    return { ok: true, data };
  } catch (error) {
    return { ok: false, error: (error as Error).message };
  }
}

// Search handler
async function handleSearch(
  searchParams: URLSearchParams,
  apiKey: string,
  origin: string | null
): Promise<Response> {
  const query = searchParams.get('query');
  const type = searchParams.get('type') || 'multi';
  const page = searchParams.get('page') || '1';
  
  if (!query) {
    return jsonResponse({ error: 'Missing query parameter' }, 400, origin);
  }
  
  const endpoint = type === 'multi' ? '/search/multi' : `/search/${type}`;
  const result = await fetchTMDB(endpoint, apiKey, { query, page });
  
  if (!result.ok) {
    return jsonResponse({ error: result.error, results: [] }, result.status || 500, origin);
  }
  
  // Add media_type to results if searching specific type
  const results = (result.data.results || []).map((item: any) => ({
    ...item,
    media_type: item.media_type || type,
    mediaType: item.media_type || type,
  }));
  
  return jsonResponse(
    { ...result.data, results },
    200,
    origin,
    CACHE_DURATIONS.search
  );
}

// Trending handler
async function handleTrending(
  searchParams: URLSearchParams,
  apiKey: string,
  origin: string | null
): Promise<Response> {
  const type = searchParams.get('type') || 'all';
  const time = searchParams.get('time') || 'week';
  const page = searchParams.get('page') || '1';
  
  const result = await fetchTMDB(`/trending/${type}/${time}`, apiKey, { page });
  
  if (!result.ok) {
    return jsonResponse({ error: result.error, results: [] }, result.status || 500, origin);
  }
  
  return jsonResponse(result.data, 200, origin, CACHE_DURATIONS.trending);
}

// Details handler
async function handleDetails(
  searchParams: URLSearchParams,
  apiKey: string,
  origin: string | null
): Promise<Response> {
  const id = searchParams.get('id');
  const type = searchParams.get('type') || 'movie';
  
  if (!id) {
    return jsonResponse({ error: 'Missing id parameter' }, 400, origin);
  }
  
  // Fetch details with append_to_response for credits, videos, etc.
  const result = await fetchTMDB(`/${type}/${id}`, apiKey, {
    append_to_response: 'credits,videos,external_ids,content_ratings,release_dates',
  });
  
  if (!result.ok) {
    return jsonResponse({ error: result.error }, result.status || 500, origin);
  }
  
  return jsonResponse(
    { ...result.data, media_type: type, mediaType: type },
    200,
    origin,
    CACHE_DURATIONS.details
  );
}

// Recommendations handler
async function handleRecommendations(
  searchParams: URLSearchParams,
  apiKey: string,
  origin: string | null
): Promise<Response> {
  const id = searchParams.get('id');
  const type = searchParams.get('type') || 'movie';
  
  if (!id) {
    return jsonResponse({ error: 'Missing id parameter' }, 400, origin);
  }
  
  // Try recommendations first
  let result = await fetchTMDB(`/${type}/${id}/recommendations`, apiKey);
  
  // Fall back to similar if recommendations empty
  if (!result.ok || !result.data?.results?.length) {
    result = await fetchTMDB(`/${type}/${id}/similar`, apiKey);
  }
  
  if (!result.ok) {
    return jsonResponse({ results: [] }, 200, origin, CACHE_DURATIONS.recommendations);
  }
  
  const results = (result.data.results || []).map((item: any) => ({
    ...item,
    media_type: type,
    mediaType: type,
  }));
  
  return jsonResponse({ results }, 200, origin, CACHE_DURATIONS.recommendations);
}

// Season handler
async function handleSeason(
  searchParams: URLSearchParams,
  apiKey: string,
  origin: string | null
): Promise<Response> {
  const id = searchParams.get('id');
  const season = searchParams.get('season');
  
  if (!id || !season) {
    return jsonResponse({ error: 'Missing id or season parameter' }, 400, origin);
  }
  
  const result = await fetchTMDB(`/tv/${id}/season/${season}`, apiKey);
  
  if (!result.ok) {
    return jsonResponse({ error: result.error }, result.status || 500, origin);
  }
  
  return jsonResponse(result.data, 200, origin, CACHE_DURATIONS.season);
}

// Movies list handler
async function handleMovies(
  searchParams: URLSearchParams,
  apiKey: string,
  origin: string | null
): Promise<Response> {
  const category = searchParams.get('category') || 'popular';
  const page = searchParams.get('page') || '1';
  
  const validCategories = ['popular', 'top_rated', 'upcoming', 'now_playing'];
  if (!validCategories.includes(category)) {
    return jsonResponse({ error: 'Invalid category' }, 400, origin);
  }
  
  const result = await fetchTMDB(`/movie/${category}`, apiKey, { page });
  
  if (!result.ok) {
    return jsonResponse({ error: result.error, results: [] }, result.status || 500, origin);
  }
  
  const results = (result.data.results || []).map((item: any) => ({
    ...item,
    media_type: 'movie',
    mediaType: 'movie',
  }));
  
  return jsonResponse({ ...result.data, results }, 200, origin, CACHE_DURATIONS.movies);
}

// Series list handler
async function handleSeries(
  searchParams: URLSearchParams,
  apiKey: string,
  origin: string | null
): Promise<Response> {
  const category = searchParams.get('category') || 'popular';
  const page = searchParams.get('page') || '1';
  
  const validCategories = ['popular', 'top_rated', 'on_the_air', 'airing_today'];
  if (!validCategories.includes(category)) {
    return jsonResponse({ error: 'Invalid category' }, 400, origin);
  }
  
  const result = await fetchTMDB(`/tv/${category}`, apiKey, { page });
  
  if (!result.ok) {
    return jsonResponse({ error: result.error, results: [] }, result.status || 500, origin);
  }
  
  const results = (result.data.results || []).map((item: any) => ({
    ...item,
    media_type: 'tv',
    mediaType: 'tv',
  }));
  
  return jsonResponse({ ...result.data, results }, 200, origin, CACHE_DURATIONS.series);
}

// Discover handler (for genre filtering)
async function handleDiscover(
  searchParams: URLSearchParams,
  apiKey: string,
  origin: string | null
): Promise<Response> {
  const type = searchParams.get('type') || 'movie';
  const page = searchParams.get('page') || '1';
  const genres = searchParams.get('genres');
  const sortBy = searchParams.get('sort_by') || 'popularity.desc';
  const year = searchParams.get('year');
  
  const params: Record<string, string> = { page, sort_by: sortBy };
  if (genres) params.with_genres = genres;
  if (year) {
    if (type === 'movie') {
      params.primary_release_year = year;
    } else {
      params.first_air_date_year = year;
    }
  }
  
  const result = await fetchTMDB(`/discover/${type}`, apiKey, params);
  
  if (!result.ok) {
    return jsonResponse({ error: result.error, results: [] }, result.status || 500, origin);
  }
  
  const results = (result.data.results || []).map((item: any) => ({
    ...item,
    media_type: type,
    mediaType: type,
  }));
  
  return jsonResponse({ ...result.data, results }, 200, origin, CACHE_DURATIONS.movies);
}

// Main handler
export async function handleTMDBRequest(
  request: Request,
  env: TMDBEnv
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/tmdb/, '').replace(/\/$/, '') || '/';
  const logLevel = (env.LOG_LEVEL || 'info') as LogLevel;
  const logger = createLogger(request, logLevel);
  const origin = request.headers.get('origin');
  
  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(origin) });
  }
  
  // Only allow GET requests
  if (request.method !== 'GET') {
    return jsonResponse({ error: 'Method not allowed' }, 405, origin);
  }
  
  // Check API key
  if (!env.TMDB_API_KEY) {
    logger.error('TMDB_API_KEY not configured');
    return jsonResponse({ error: 'TMDB API key not configured' }, 500, origin);
  }
  
  // Health check
  if (path === '/health' || path === '') {
    return jsonResponse({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      hasApiKey: !!env.TMDB_API_KEY,
    }, 200, origin);
  }
  
  const searchParams = url.searchParams;
  
  // Route handlers
  switch (path) {
    case '/search':
      return handleSearch(searchParams, env.TMDB_API_KEY, origin);
      
    case '/trending':
      return handleTrending(searchParams, env.TMDB_API_KEY, origin);
      
    case '/details':
      return handleDetails(searchParams, env.TMDB_API_KEY, origin);
      
    case '/recommendations':
      return handleRecommendations(searchParams, env.TMDB_API_KEY, origin);
      
    case '/season':
      return handleSeason(searchParams, env.TMDB_API_KEY, origin);
      
    case '/movies':
      return handleMovies(searchParams, env.TMDB_API_KEY, origin);
      
    case '/series':
      return handleSeries(searchParams, env.TMDB_API_KEY, origin);
      
    case '/discover':
      return handleDiscover(searchParams, env.TMDB_API_KEY, origin);
      
    default:
      return jsonResponse({ error: 'Not found' }, 404, origin);
  }
}

export default {
  fetch: handleTMDBRequest,
};
