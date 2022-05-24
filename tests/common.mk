IDA_DIR=/home/user/idapro-7.7/
SYMLESS_DIR=/home/user/Desktop/symless/

ifeq (${bitness}, 64)
	ext=i64
	ifdef IDA_DIR
		ida=${IDA_DIR}/ida64
	endif
else ifeq (${bitness}, 32)
	ext=idb
	ifdef IDA_DIR
		ida=${IDA_DIR}/ida
	endif
endif


target_idb=${target}.${ext}
result_idb=${target}.symless.${ext}

libs_rel_path=../../../bin/
utils_path=../../../utils


.PHONY: default
default:
	@echo "Available targets:"
	@echo "\tapply      : apply symless on target"
	@echo "\tclean      : clean working directory"
	@echo "\tdump       : create database dump"
	@echo "\tida        : open symless database"
	@echo "\tida-clean  : open clean database"

.PHONY: check_ida
check_ida:
	@if test -z "${ida}"; then echo "Missing IDA_DIR env"; exit 1; fi

.PHONY: check_symless
check_symless:
	@if test -z "${SYMLESS_DIR}"; then echo "Missing SYMLESS_DIR env"; exit 1; fi

.PHONY: check_target
check_target:
	@if test -z "${target}"; then echo "Please specify a target in your Makefile"; exit 1; fi
	@if test -z "${bitness}"; then echo "Please specify a bitness in your Makefile"; exit 1; fi

.PHONY: apply check_target check_symless
apply: ${result_idb}

.PHONY: dump check_target check_symless
dump: ${result_idb}
	mkdir -p dump
	python3 ${SYMLESS_DIR}/run_script.py ${utils_path}/dump.py ${result_idb} > dump/${target}_$(shell git rev-parse HEAD).dump

.PHONY: ida
ida: ${result_idb} check_ida check_target
	${ida} ${result_idb} &

.PHONY: ida-clean
ida-clean: ${target_idb} check_ida check_target
	${ida} ${target_idb} &

.PHONY: clean
clean: base check_target
	rm ${target}.* 2> /dev/null; cp ${libs_rel_path}/${target_idb} ./

${result_idb}: ${target_idb}
	cp ${target_idb} ${result_idb} && python3 ${SYMLESS_DIR}/symless.py ${result_idb}

${target_idb}: ${libs_rel_path}/${target_idb}
	cp ${libs_rel_path}/${target_idb} ./

.PHONY: base
base: check_target check_symless ${libs_rel_path}/${target_idb}

.PHONY: all
all:
	cd win64/cabview
	make clean && make apply && make dump
	cd ../../

${libs_rel_path}/${target_idb}: ${libs_rel_path}/${target}
	python3 ${SYMLESS_DIR}/run_script.py "" ${libs_rel_path}/${target}
