.PHONY: all list-projects clean

DOCKER_IMAGE ?= aabadie/dotbot:latest
DOCKER_TARGETS ?= all
PACKAGES_DIR_OPT ?=
SEGGER_DIR ?= /opt/segger
BUILD_CONFIG ?= Debug
NRF_TARGET ?= nrf52833
PROJECT_FILE ?= dotbot-firmware-$(NRF_TARGET).emProject

ifeq (nrf5340-app,$(NRF_TARGET))
  PROJECTS ?= 01bsp_gpio 01bsp_i2c 01bsp_motors 01drv_pid 01bsp_rpm 01bsp_timer 01bsp_timer_hf 01bsp_uart
else
  PROJECTS ?= $(shell find projects/ -maxdepth 1 -mindepth 1 -type d | tr -d "/" | sed -e s/projects// | sort)
endif
SRCS ?= $(shell find bsp/ -name "*.[c|h]") $(shell find drv/ -name "*.[c|h]") $(shell find projects/ -name "*.[c|h]")
CLANG_FORMAT ?= clang-format
CLANG_FORMAT_TYPE ?= file

ARTIFACT_PROJECTS ?= 03app_dotbot 03app_sailbot 03app_dotbot_gateway
ARTIFACT_ELF = $(foreach app,$(ARTIFACT_PROJECTS),projects/$(app)/Output/$(NRF_TARGET)/$(BUILD_CONFIG)/Exe/$(app)-$(NRF_TARGET).elf)
ARTIFACT_HEX = $(ARTIFACT_ELF:.elf=.hex)


.PHONY: $(PROJECTS) $(ARTIFACT_PROJECTS) artifacts docker docker-release format check-format

all: $(PROJECTS)

$(PROJECTS):
	@echo "\e[1mBuilding project $@\e[0m"
	"$(SEGGER_DIR)/bin/emBuild" $(PROJECT_FILE) -project $@ -config $(BUILD_CONFIG) $(PACKAGES_DIR_OPT) -rebuild -verbose
	@echo "\e[1mDone\e[0m\n"

list-projects:
	@echo "\e[1mAvailable projects:\e[0m"
	@echo $(PROJECTS) | tr ' ' '\n'

clean:
	"$(SEGGER_DIR)/bin/emBuild" $(PROJECT_FILE) -config $(BUILD_CONFIG) -clean
	rm -f $(ARTIFACT_HEX)

format:
	@$(CLANG_FORMAT) -i --style=$(CLANG_FORMAT_TYPE) $(SRCS)

check-format:
	@$(CLANG_FORMAT) --dry-run --Werror --style=$(CLANG_FORMAT_TYPE) $(SRCS)

$(ARTIFACT_ELF): $(ARTIFACT_PROJECTS)

$(ARTIFACT_HEX): $(ARTIFACT_ELF)
	objcopy -O ihex $(subst .hex,.elf,$@) $@

artifacts: $(ARTIFACT_HEX)
	@mkdir -p artifacts
	@for artifact in "$(ARTIFACT_ELF) $(ARTIFACT_HEX)"; do \
		cp $${artifact} artifacts/.; \
		done
	@ls -l artifacts/

docker:
	docker run --rm -i \
		-e NRF_TARGET="$(NRF_TARGET)" \
		-e BUILD_CONFIG="$(BUILD_CONFIG)" \
		-e PACKAGES_DIR_OPT="-packagesdir $(SEGGER_DIR)/packages" \
		-e PROJECTS="$(PROJECTS)" \
		-e SEGGER_DIR="$(SEGGER_DIR)" \
		-v $(PWD):/dotbot $(DOCKER_IMAGE) \
		make $(DOCKER_TARGETS)
