.PHONY: serve serve-container ship secure scrap

# Define color codes
BLUE := \033[1;34m
RESET := \033[0m

# Get remaining arguments after the target
ARGS := $(wordlist 2, $(words $(MAKECMDGOALS)), $(MAKECMDGOALS))

# Define a function to execute commands with nice output and handle arguments
# Usage: $(call task,command)
define task
@printf "Make => $(BLUE)$(1) $(ARGS)$(RESET)\n"
@$(1) $(ARGS)
@exit 0
endef

# Run application server
serve:
	$(call task,python app/main.py)

# Run in Docker container
serve-container:
	@printf "Make => $(BLUE)Running in container$(RESET)\n"
	@sh -c 'DIR=$${PWD##*/} && \
	docker rm -f $$DIR-web || true && \
	docker buildx build --force-rm=true --no-cache -t $$DIR-web . && \
	docker run --rm --name $$DIR-web -p 8000:8000 -v ~/.aws:/root/.aws:ro $$DIR-web'

# Deployment tasks
ship:
	$(call task,python deployment/manage.py ship)

secure:
	$(call task,python deployment/manage.py secure)

scrap:
	$(call task,python deployment/manage.py scrap)

# Prevent Make from treating extra args as targets
%:
	@: