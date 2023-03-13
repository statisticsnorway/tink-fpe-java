.PHONY: default
default: | help

.PHONY: build
build: ## Build the project and install to you local maven repo
	mvn clean install

.PHONY: release-dryrun
release-dryrun: ## Simulate a release in order to detect any issues
	mvn release:prepare release:perform -Darguments="-Dmaven.deploy.skip=true" -DdryRun=true

.PHONY: release
release: ## Release a new version. Update POMs and tag the new version in git. Pipeline will deploy upon tag detection.
	mvn release:prepare release:perform -Darguments="-Dmaven.deploy.skip=true -Dmaven.javadoc.skip=true"

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
