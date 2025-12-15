# Changelog

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
