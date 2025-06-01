CXX = g++
CXXFLAGS = -std=c++17 -g
LDFLAGS = -lcapstone

SDB_SRC = sdb.cpp
SDB_OBJ = $(SDB_SRC:.cpp=.o)
SDB_EXEC = sdb

# 在這裡定義您的測試案例
# 格式: TEST_ID:TEST_NAME_ARG:TEST_PROGRAM_ARG
TESTS := \
    ex1-1:ex1-1:hello \
    ex2:ex2:hello \
    ex3:ex3:rana \
    ex4:ex4:hello \
	ex5:ex5:anon \
	ex6:ex6:hello \
	ex7:ex7:hello \
	ex8:ex8:hello 

# 測試腳本的路徑
TEST_SCRIPT = ./test-script.sh

# 從 TESTS 變數中提取所有唯一的 TEST_ID
ALL_TEST_IDS_FROM_CONFIG := $(foreach test_entry,$(TESTS),$(firstword $(subst :, ,$(test_entry))))
UNIQUE_TEST_IDS := $(sort $(ALL_TEST_IDS_FROM_CONFIG))

.PHONY: all clean test $(UNIQUE_TEST_IDS)

all: $(SDB_EXEC)

$(SDB_EXEC): $(SDB_OBJ)
	$(CXX) $(SDB_OBJ) -o $@ $(LDFLAGS)

$(SDB_OBJ): $(SDB_SRC)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 定义一個宏來產生執行單個測試的 shell 命令
# 參數: $(1) = TEST_ID, $(2) = TEST_NAME_ARG, $(3) = TEST_PROGRAM_ARG
define RUN_TEST_SHELL_CMDS
echo ""; \
echo "===> 執行測試案例 ID: $(1) (腳本參數: $(2), $(3))"; \
if $(TEST_SCRIPT) "$(2)" "$(3)"; then \
    echo "===> 測試案例 ID: $(1) 成功"; \
else \
    echo "===> 測試案例 ID: $(1) 失敗"; \
    exit 1; \
fi;
endef

# 測試目標
test: all
	@# 提取 "test" 後面傳遞的參數
	@$(eval CMD_GOALS := $(MAKECMDGOALS))
	@$(eval ARGS_AFTER_TEST_TARGET := $(filter-out $@,$(CMD_GOALS)))

	@# 篩選出已知的測試 ID 及未知的參數
	@$(eval KNOWN_TEST_IDS_IN_ARGS := $(filter $(UNIQUE_TEST_IDS), $(ARGS_AFTER_TEST_TARGET)))
	@$(eval UNKNOWN_ARGS_IN_CMD := $(filter-out $(UNIQUE_TEST_IDS) test, $(ARGS_AFTER_TEST_TARGET))) # 從參數中排除 'test' 本身

	@if [ ! -z "$(UNKNOWN_ARGS_IN_CMD)" ]; then \
		echo "" >&2; \
		echo "錯誤：指定的測試 ID 或參數未定義: '$(UNKNOWN_ARGS_IN_CMD)'" >&2; \
		echo "已定義的測試 ID 有: $(UNIQUE_TEST_IDS)" >&2; \
		echo "用法: make test [可選的測試ID_1 可選的測試ID_2 ...]" >&2; \
		echo "" >&2; \
		exit 1; \
	fi

	@if [ -z "$(ARGS_AFTER_TEST_TARGET)" ] || [ "$(strip $(ARGS_AFTER_TEST_TARGET))" = "test" ]; then \
		echo "--- 執行所有已定義的測試案例 ---"; \
		$(foreach test_entry,$(TESTS), \
			$(eval CURRENT_TEST_ID_TMP := $(word 1,$(subst :, ,$(test_entry)))) \
			$(eval TEST_NAME_ARG_TMP := $(word 2,$(subst :, ,$(test_entry)))) \
			$(eval TEST_PROGRAM_ARG_TMP := $(word 3,$(subst :, ,$(test_entry)))) \
			$(call RUN_TEST_SHELL_CMDS,$(CURRENT_TEST_ID_TMP),$(TEST_NAME_ARG_TMP),$(TEST_PROGRAM_ARG_TMP)) \
		) \
		echo ""; \
		echo "--- 所有已定義的測試案例執行完畢 ---"; \
	elif [ ! -z "$(KNOWN_TEST_IDS_IN_ARGS)" ]; then \
		echo "--- 執行指定的測試案例: $(KNOWN_TEST_IDS_IN_ARGS) ---"; \
		$(foreach specific_id,$(KNOWN_TEST_IDS_IN_ARGS), \
			$(eval FOUND_TEST_ENTRY := $(filter $(specific_id):%,$(TESTS))) \
			$(eval TEST_NAME_ARG_TMP := $(word 2,$(subst :, ,$(FOUND_TEST_ENTRY)))) \
			$(eval TEST_PROGRAM_ARG_TMP := $(word 3,$(subst :, ,$(FOUND_TEST_ENTRY)))) \
			$(call RUN_TEST_SHELL_CMDS,$(specific_id),$(TEST_NAME_ARG_TMP),$(TEST_PROGRAM_ARG_TMP)) \
		) \
		echo ""; \
		echo "--- 指定的測試案例執行完畢 ---"; \
	else \
		echo "Makefile 內部錯誤或非預期的參數組合。請檢查參數。" >&2; \
		exit 1; \
	fi

# 為每個測試 ID 添加一個空的 recipe。
$(UNIQUE_TEST_IDS):
	@: # 虛設目標

clean:
	rm -f $(SDB_EXEC) $(SDB_OBJ) core.* *.o
	rm -rf ./output/
	@echo "已清理 sdb 建置檔案和測試輸出。"

