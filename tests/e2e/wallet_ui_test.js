/**
 * UI flow tests for the Sovereign Wallet onboarding credential protection.
 *
 * Mocks the browser DOM environment in Node and executes the client script
 * to verify seed/password mask toggle invariants.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function runUiTests() {
    console.log("🧪 Running E2E Wallet UI Logic Tests...");

    // Mock Elements
    const elements = {
        'seed-input': { id: 'seed-input', value: '0x1234abcd', type: 'password', textContent: '' },
        'password-input': { id: 'password-input', value: 'safePass123', type: 'password', textContent: '' },
        'reveal-seed-btn': { id: 'reveal-seed-btn', type: 'button', textContent: '👁️ Reveal', listeners: {} },
        'reveal-password-btn': { id: 'reveal-password-btn', type: 'button', textContent: '👁️ Reveal', listeners: {} },
        'select-dir-btn': { id: 'select-dir-btn', listeners: {} },
        'generate-keys-btn': { id: 'generate-keys-btn', listeners: {} },
        'dir-status': { id: 'dir-status', textContent: '' }
    };

    // Helper to add event listener to mock elements
    for (const key in elements) {
        if (!elements[key].listeners) {
            elements[key].listeners = {};
        }
        elements[key].addEventListener = function(event, callback) {
            this.listeners[event] = callback;
        };
    }

    // Mock Globals
    let alertMsg = null;
    let promptReturnValue = null;
    let promptCallCount = 0;
    let promptQuestion = null;

    const mockWindow = {
        console: {
            log: (...args) => console.log("   [Browser Console.log]:", ...args),
            error: (...args) => console.error("   [Browser Console.error]:", ...args)
        },
        document: {
            getElementById: (id) => {
                return elements[id] || { addEventListener: () => {}, appendChild: () => {}, textContent: '' };
            },
            createElement: (tagName) => {
                return {
                    className: '',
                    innerHTML: '',
                    appendChild: () => {}
                };
            }
        },
        alert: (msg) => {
            alertMsg = msg;
        },
        prompt: (question) => {
            promptCallCount++;
            promptQuestion = question;
            return promptReturnValue;
        },
        wasm_bindgen: (bytes) => {
            console.log("   [Mock WASM initialized]");
            return Promise.resolve();
        },
        wasmBytes: new Uint8Array([1, 2, 3]),
        TextEncoder: class { encode(str) { return new Uint8Array(Buffer.from(str)); } },
        TextDecoder: class { decode(bytes) { return Buffer.from(bytes).toString(); } }
    };

    mockWindow.window = mockWindow;

    // Load app.js
    const appJsPath = path.resolve(__dirname, '../../wallet/www/app.js');
    const appJsContent = fs.readFileSync(appJsPath, 'utf8');

    // Execute script inside sandboxed VM context
    const context = vm.createContext(mockWindow);
    vm.runInContext(appJsContent, context);

    // Assert: Check that event listeners were registered
    assert.ok(elements['reveal-seed-btn'].listeners['click'], "reveal-seed-btn click listener not registered");
    assert.ok(elements['reveal-password-btn'].listeners['click'], "reveal-password-btn click listener not registered");

    console.log("  ... Event listeners successfully registered.");

    // --- Test Case 1: Reveal Seed with Incorrect Password ---
    console.log("  ... Sub-Test 1: Reveal seed with incorrect password...");
    promptReturnValue = "wrong_password";
    alertMsg = null;
    elements['reveal-seed-btn'].listeners['click']();
    assert.strictEqual(elements['seed-input'].type, 'password', "Seed input type should remain 'password'");
    assert.strictEqual(alertMsg, "Incorrect password.", "Incorrect password alert not triggered");
    console.log("    ... Correctly blocked reveal on incorrect password.");

    // --- Test Case 2: Reveal Seed with Correct Password ---
    console.log("  ... Sub-Test 2: Reveal seed with correct password...");
    promptReturnValue = "safePass123";
    alertMsg = null;
    elements['reveal-seed-btn'].listeners['click']();
    assert.strictEqual(elements['seed-input'].type, 'text', "Seed input type should change to 'text'");
    assert.strictEqual(elements['reveal-seed-btn'].textContent, '🔒 Hide', "Button text should toggle to 'Hide'");
    console.log("    ... Correctly revealed seed on validation success.");

    // --- Test Case 3: Hide Seed ---
    console.log("  ... Sub-Test 3: Hide seed again...");
    elements['reveal-seed-btn'].listeners['click']();
    assert.strictEqual(elements['seed-input'].type, 'password', "Seed input type should revert to 'password'");
    assert.strictEqual(elements['reveal-seed-btn'].textContent, '👁️ Reveal', "Button text should revert to 'Reveal'");
    console.log("    ... Correctly hid seed on toggle.");

    // --- Test Case 4: Reveal Password with Correct Confirmation ---
    console.log("  ... Sub-Test 4: Reveal password with correct confirmation...");
    promptReturnValue = "safePass123";
    alertMsg = null;
    elements['reveal-password-btn'].listeners['click']();
    assert.strictEqual(elements['password-input'].type, 'text', "Password input type should change to 'text'");
    assert.strictEqual(elements['reveal-password-btn'].textContent, '🔒 Hide', "Button text should toggle to 'Hide'");
    console.log("    ... Correctly revealed backup password on validation success.");

    // --- Test Case 5: Hide Password ---
    console.log("  ... Sub-Test 5: Hide password again...");
    elements['reveal-password-btn'].listeners['click']();
    assert.strictEqual(elements['password-input'].type, 'password', "Password input type should revert to 'password'");
    assert.strictEqual(elements['reveal-password-btn'].textContent, '👁️ Reveal', "Button text should revert to 'Reveal'");
    console.log("    ... Correctly hid backup password on toggle.");

    console.log("\n🎉 All E2E Wallet UI Logic Tests Passed!");
}

runUiTests();
