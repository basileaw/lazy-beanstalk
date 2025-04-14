.PHONY: serve serve-container ship secure scrap

# Include environment variables
ifneq (,$(wildcard .env))
    include .env
    export
endif

# Define color codes
BLUE := \033[1;34m
RESET := \033[0m

# Get remaining arguments after the target
ARGS := $(wordlist 2, $(words $(MAKECMDGOALS)), $(MAKECMDGOALS))

# Define a function to execute commands with nice output and handle arguments
# Usage: $(call task,command)
define task
@printf "Make => $(BLUE)$(1) $(ARGS)$(RESET)\n"
@set -a; [ -f .env ] && . .env; set +a; $(1) $(ARGS); \
status=$$?; \
if [ $$status -eq 130 ]; then \
    printf "\n$(BLUE)Process terminated by user$(RESET)\n"; \
    exit 0; \
else \
    exit $$status; \
fi
endef

# Run application server
serve:
	$(call task,python app/main.py)

serve-container:
	$(call task,docker compose up --build)

# Deployment tasks
ship:
	$(call task,python deployment/manage.py ship)

secure:
	$(call task,python deployment/manage.py secure)

shield:
	$(call task,python deployment/manage.py shield)

scrap:
	$(call task,python deployment/manage.py scrap)

# Prevent Make from treating extra args as targets
%:
	@: