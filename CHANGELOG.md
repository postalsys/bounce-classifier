# Changelog

## [3.0.0](https://github.com/postalsys/bounce-classifier/compare/v2.4.0...v3.0.0) (2026-04-23)


### ⚠ BREAKING CHANGES

* getModelInfo() no longer returns null before init; it always returns an object. Use the new `initialized` flag instead of a null-check.

### Features

* classifyBatch, custom fallbacks, streaming init, demo UX overhaul ([1bae2c3](https://github.com/postalsys/bounce-classifier/commit/1bae2c37384124b4c3ab50b8a267354f26d32d9a))


### Bug Fixes

* prevent extractSmtpCodes from matching IPv4 octets ([665d332](https://github.com/postalsys/bounce-classifier/commit/665d332de73e4dc160ba788c237fc6bc6627a5c3))

## [2.4.0](https://github.com/postalsys/bounce-classifier/compare/v2.3.0...v2.4.0) (2026-03-16)


### Features

* add update-model script and prepublish hook ([bb3625d](https://github.com/postalsys/bounce-classifier/commit/bb3625d82d571e293efe07118836a3b00318442e))


### Bug Fixes

* make ambiguous classification tests model-resilient ([c57588d](https://github.com/postalsys/bounce-classifier/commit/c57588dc7c3287425c18553a70d3c4e453fa14ca))

## [2.3.0](https://github.com/postalsys/bounce-classifier/compare/v2.2.0...v2.3.0) (2026-03-16)


### Features

* add text pattern fallbacks for rate_limited classification ([629ef10](https://github.com/postalsys/bounce-classifier/commit/629ef1082cf6a45c28bac5fab7a40ac32832ac85))

## [2.2.0](https://github.com/postalsys/bounce-classifier/compare/v2.1.0...v2.2.0) (2026-03-16)


### Features

* add getModelInfo() and model hash versioning ([36e57e0](https://github.com/postalsys/bounce-classifier/commit/36e57e0019b553caf9bc6c2fe0deffb2a05b1145))

## [2.1.0](https://github.com/postalsys/bounce-classifier/compare/v2.0.0...v2.1.0) (2026-03-16)


### Features

* add reload() method for live model updates ([72da12a](https://github.com/postalsys/bounce-classifier/commit/72da12a3d88cb471a000bf85a5b598a343277a16))


### Bug Fixes

* update tests for retrained model and clean up lint ([274e23f](https://github.com/postalsys/bounce-classifier/commit/274e23fb626c43d3e1a9037df7fa8614471054e6))

## [2.0.0](https://github.com/postalsys/bounce-classifier/compare/v1.2.1...v2.0.0) (2025-12-15)


### ⚠ BREAKING CHANGES

* Remove classifyBatch() API - use classify() in a loop instead

### Bug Fixes

* improve classification accuracy with text pattern priority ([85d0319](https://github.com/postalsys/bounce-classifier/commit/85d03194b8d23b517aa992bbb470daaefe5d39e0))
* improve virus_detected classification with text pattern fallbacks ([798ca30](https://github.com/postalsys/bounce-classifier/commit/798ca30f41ce75286f326c1b2b35910bd7f8fda0))
* use dynamic imports for browser compatibility ([88850ca](https://github.com/postalsys/bounce-classifier/commit/88850ca0803f723d58301cd8d5e317fe50fc98c5))
* use static requires in CJS bundle for pkg compatibility ([873adc9](https://github.com/postalsys/bounce-classifier/commit/873adc998a45da529b1368da41b75eaa74774337))


### Code Refactoring

* replace TensorFlow.js with pure JS inference ([8f05baa](https://github.com/postalsys/bounce-classifier/commit/8f05baac7c7a6a30d79f5d96717f48ba64c20f43))

## [1.2.1](https://github.com/postalsys/bounce-classifier/compare/v1.2.0...v1.2.1) (2025-12-14)


### Bug Fixes

* add input sanitization, improve error handling, and setup ESLint ([4fad0f2](https://github.com/postalsys/bounce-classifier/commit/4fad0f23c9c2d2ac730af85070034d803d7b92fb))
* replace dynamic imports with createRequire for pkg compatibility ([0b23b65](https://github.com/postalsys/bounce-classifier/commit/0b23b659f900069cb02007661105efcbaad0e710))

## [1.2.0](https://github.com/postalsys/bounce-classifier/compare/v1.1.0...v1.2.0) (2025-12-14)


### Features

* retrain model with expanded training data ([93779ef](https://github.com/postalsys/bounce-classifier/commit/93779ef187b545658f1101dd20a5b0c512042ae3))

## [1.1.0](https://github.com/postalsys/bounce-classifier/compare/v1.0.0...v1.1.0) (2025-12-14)


### Features

* add comprehensive unit tests with Node.js test runner ([932edf5](https://github.com/postalsys/bounce-classifier/commit/932edf5aacf4409b6517043ac8644f1a57c97b20))


### Bug Fixes

* trigger initial release ([bb6ab4f](https://github.com/postalsys/bounce-classifier/commit/bb6ab4f386faf1b9b5ea0f91f7c514c835f667fe))
