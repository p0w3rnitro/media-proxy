/**
 * Test script for the Analytics Proxy
 * Run: node test-analytics.js
 * 
 * Make sure the worker is running locally first:
 * npx wrangler dev
 */

const WORKER_URL = process.env.WORKER_URL || 'http://localhost:8787';

async function testHealth() {
  console.log('\n=== Testing /analytics/health ===');
  try {
    const res = await fetch(`${WORKER_URL}/analytics/health`);
    const data = await res.json();
    console.log('Status:', res.status);
    console.log('Response:', JSON.stringify(data, null, 2));
    return res.ok;
  } catch (error) {
    console.error('Error:', error.message);
    return false;
  }
}

async function testPresence() {
  console.log('\n=== Testing /analytics/presence ===');
  try {
    const payload = {
      userId: 'test_user_123',
      sessionId: 'test_session_456',
      activityType: 'browsing',
      contentTitle: 'Test Page',
      isActive: true,
      isVisible: true,
      validation: {
        isBot: false,
        botConfidence: 0,
        hasInteracted: true,
        interactionCount: 5,
        mouseEntropy: 0.6,
        mouseSamples: 100,
      },
      timestamp: Date.now(),
    };
    
    const res = await fetch(`${WORKER_URL}/analytics/presence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    console.log('Status:', res.status);
    console.log('Response:', JSON.stringify(data, null, 2));
    return res.ok;
  } catch (error) {
    console.error('Error:', error.message);
    return false;
  }
}

async function testPageView() {
  console.log('\n=== Testing /analytics/pageview ===');
  try {
    const payload = {
      userId: 'test_user_123',
      sessionId: 'test_session_456',
      pagePath: '/test/page',
      pageTitle: 'Test Page Title',
      referrer: 'https://google.com',
    };
    
    const res = await fetch(`${WORKER_URL}/analytics/pageview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    console.log('Status:', res.status);
    console.log('Response:', JSON.stringify(data, null, 2));
    return res.ok;
  } catch (error) {
    console.error('Error:', error.message);
    return false;
  }
}

async function testEvent() {
  console.log('\n=== Testing /analytics/event ===');
  try {
    const payload = {
      sessionId: 'test_session_456',
      eventType: 'button_click',
      metadata: {
        buttonId: 'play-button',
        contentId: 'movie_123',
      },
    };
    
    const res = await fetch(`${WORKER_URL}/analytics/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    console.log('Status:', res.status);
    console.log('Response:', JSON.stringify(data, null, 2));
    return res.ok;
  } catch (error) {
    console.error('Error:', error.message);
    return false;
  }
}

async function runTests() {
  console.log('Testing Analytics Proxy at:', WORKER_URL);
  console.log('='.repeat(50));
  
  const results = {
    health: await testHealth(),
    presence: await testPresence(),
    pageview: await testPageView(),
    event: await testEvent(),
  };
  
  console.log('\n' + '='.repeat(50));
  console.log('Test Results:');
  Object.entries(results).forEach(([test, passed]) => {
    console.log(`  ${test}: ${passed ? '✓ PASSED' : '✗ FAILED'}`);
  });
  
  const allPassed = Object.values(results).every(r => r);
  console.log('\nOverall:', allPassed ? '✓ ALL TESTS PASSED' : '✗ SOME TESTS FAILED');
  
  process.exit(allPassed ? 0 : 1);
}

runTests();
