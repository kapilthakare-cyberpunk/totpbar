# TOTPBar Mac App Store Preparation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare TOTPBar for Mac App Store submission by adding Info.plist metadata, Keychain persistence, App Sandbox entitlements, QR code scanning (camera + clipboard + manual entry), onboarding/empty state, and build verification.

**Architecture:** Extend the existing single-file Swift app (`TOTPBar.swift`) to include robust macOS Keychain storage, a native Add Account / Manual Entry dialog, AVCapture/Vision QR code scanning, onboarding empty state, and proper Mac App Store configuration files (`Info.plist` and `TOTPBar.entitlements`).

**Tech Stack:** Swift 5.9+, AppKit, CryptoKit, Security (Keychain), AVFoundation, Vision, UserNotifications.

**Spec:** User requirements for Mac App Store readiness.

## Global Constraints
- Bundle ID: `com.kapilthakare.totpbar`
- Version: `1.0.0`, Build: `1`
- Minimum macOS: `13.0`
- LSUIElement: `true` (menu bar only)
- Copyright: `Kapil Thakare`
- Entitlements: App Sandbox enabled (`com.apple.security.app-sandbox`), Camera access (`com.apple.security.device.camera`).

## Review Focus
- **Keychain Migration & Persistence:** Ensuring existing plaintext `accounts.txt` entries migrate securely to Keychain on first launch, and subsequent additions persist across app restarts.
- **QR Code Scanning & Manual Entry:** Handling camera permissions gracefully and parsing manual or clipboard `otpauth://` URIs correctly.
- **Onboarding Experience:** Clear guidance and empty state prompts when no accounts are configured.

---

## Tasks

### Task 1: Create `Info.plist` and `TOTPBar.entitlements`

**Files:**
- Create: `Info.plist`
- Create: `TOTPBar.entitlements`
- Modify: `Package.swift` (if needed for bundle/plist embedding)

**Interfaces:**
- Consumes: None
- Produces: App Store metadata and sandbox configuration.

- [ ] **Step 1: Write `Info.plist` with required metadata**
- [ ] **Step 2: Write `TOTPBar.entitlements` with App Sandbox and camera usage**
- [ ] **Step 3: Verify plist and entitlements syntax**

### Task 2: Implement Keychain Persistence for TOTP Secrets

**Files:**
- Modify: `TOTPBar.swift`

**Interfaces:**
- Consumes: `Account` model
- Produces: `saveAccountToKeychain(_:)`, `loadAccountsFromKeychain()`, migration from `accounts.txt`.

- [ ] **Step 1: Add Keychain helper functions for generic password storage and retrieval**
- [ ] **Step 2: Update `load()` and account saving logic to use Keychain with plaintext `accounts.txt` migration fallback**
- [ ] **Step 3: Verify secrets survive app restart and are not stored in plaintext**

### Task 3: Implement Manual Entry & Clipboard / QR Import UI

**Files:**
- Modify: `TOTPBar.swift`

**Interfaces:**
- Consumes: Account parsing logic
- Produces: Add Account window / NSAlert dialog, clipboard URI parser, camera QR scanner.

- [ ] **Step 1: Implement manual account entry dialog (Secret, Label, Issuer, Digits, Period, Algorithm)**
- [ ] **Step 2: Implement clipboard `otpauth://` URI import function**
- [ ] **Step 3: Implement camera QR scanning using AVFoundation / CoreImage / Vision**
- [ ] **Step 4: Add menu items for "Add Account...", "Scan QR Code...", and "Import from Clipboard"**

### Task 4: Add Onboarding & Empty State Experience

**Files:**
- Modify: `TOTPBar.swift`

**Interfaces:**
- Consumes: Account list state
- Produces: First-launch welcome and empty state prompt.

- [ ] **Step 1: Detect first launch / empty accounts state**
- [ ] **Step 2: Display welcoming onboarding alert explaining permissions (Keychain, Camera) and prompting to add the first token**
- [ ] **Step 3: Update menu rebuild empty state to offer direct action to add an account**

### Task 5: Build Verification and Final Testing

**Files:**
- Modify: `TOTPBar.swift` and package configuration as needed.

**Interfaces:**
- Consumes: All implemented features
- Produces: Successful `swift build` and verified app behavior.

- [ ] **Step 1: Run `swift build` to verify compilation**
- [ ] **Step 2: Verify TOTP code generation, ConcealedType clipboard copying, and countdown updates**
- [ ] **Step 3: Commit all changes with clear messages**
