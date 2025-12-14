/**
 * Simple test for bounce-classifier
 */

import { classify, classifyBatch, initialize, getLabels, isReady, reset } from '../src/index.js';
import assert from 'assert';

const testCases = [
    { msg: '550 5.1.1 User Unknown', expected: 'user_unknown' },
    { msg: '552 5.2.2 Mailbox full', expected: 'mailbox_full' },
    { msg: '421 4.7.0 Try again later', expected: 'rate_limited' },
    { msg: '550 IP blocked by zen.spamhaus.org', expected: 'ip_blacklisted' },
    { msg: '550 5.7.1 DMARC policy rejection', expected: 'auth_failure' },
    { msg: '451 4.3.0 Server error', expected: 'server_error' },
];

async function runTests() {
    console.log('Running bounce-classifier tests...\n');

    // Test initialization
    console.log('1. Testing initialization...');
    assert.strictEqual(isReady(), false, 'Should not be ready before init');
    await initialize();
    assert.strictEqual(isReady(), true, 'Should be ready after init');
    console.log('   PASS: Initialization works\n');

    // Test getLabels
    console.log('2. Testing getLabels...');
    const labels = await getLabels();
    assert.strictEqual(labels.length, 16, 'Should have 16 labels');
    assert.ok(labels.includes('user_unknown'), 'Should include user_unknown');
    console.log('   PASS: getLabels returns correct labels\n');

    // Test single classification
    console.log('3. Testing single classification...');
    for (const { msg, expected } of testCases) {
        const result = await classify(msg);
        console.log(`   "${msg.substring(0, 40)}..." -> ${result.label} (${(result.confidence * 100).toFixed(0)}%)`);
        assert.ok(result.label, 'Should have a label');
        assert.ok(typeof result.confidence === 'number', 'Should have confidence');
        assert.ok(result.action, 'Should have action');
        assert.ok(result.scores, 'Should have scores');
    }
    console.log('   PASS: Single classification works\n');

    // Test batch classification
    console.log('4. Testing batch classification...');
    const messages = testCases.map(t => t.msg);
    const results = await classifyBatch(messages);
    assert.strictEqual(results.length, messages.length, 'Should return same number of results');
    results.forEach((result, i) => {
        assert.ok(result.label, `Result ${i} should have label`);
    });
    console.log('   PASS: Batch classification works\n');

    // Test blocklist identification
    console.log('5. Testing blocklist identification...');
    const blResult = await classify('550 blocked by spamhaus.org zen list');
    assert.ok(blResult.blocklist, 'Should identify blocklist');
    // Blocklist can be single object or have lists array
    const blName = blResult.blocklist.name || (blResult.blocklist.lists && blResult.blocklist.lists[0]?.name);
    assert.ok(blName, 'Should have blocklist name');
    console.log(`   Identified: ${blName}`);
    console.log('   PASS: Blocklist identification works\n');

    // Test reset
    console.log('6. Testing reset...');
    reset();
    assert.strictEqual(isReady(), false, 'Should not be ready after reset');
    console.log('   PASS: Reset works\n');

    console.log('All tests passed!');
}

runTests().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
});
