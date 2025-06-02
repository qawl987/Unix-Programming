#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm> // For std::min, std::find_if
#include <map>       // For breakpoints
#include <memory>

#include <cerrno>  // For errno
#include <cstring> // For strerror, strncpy, memcpy
#include <csignal> // For kill, SIGKILL, SIGTRAP
#include <cstdlib> // For exit, realpath
#include <climits> // For PATH_MAX

#include <unistd.h> // fork, execvp, getpid
#include <fcntl.h>  // open, O_RDONLY
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h> // For user_regs_struct
#include <elf.h>      // Elf64_Ehdr, Elf64_Phdr, Elf64_auxv_t

#include <capstone/capstone.h>

// Forward declare structs if they are only used by Debugger and defined within it,
// or keep them outside if they are fundamental types shared widely (like MemoryRegion).
// For Breakpoint, it's tightly coupled with the debugger's state.
struct MemoryRegion
{
    unsigned long long start;
    unsigned long long end;
    std::string perms;
    std::string path;
};

// Standalone function
void print_prompt()
{
    std::cout << "(sdb) ";
    std::cout.flush();
}

class Debugger
{
public:
    Debugger();
    ~Debugger();

    // Public interface for commands
    bool load_program(const std::string &program_path_arg);
    void step_instruction();
    void continue_execution();
    void set_breakpoint(const std::string &val_str, bool is_rva);
    void info_breakpoints() const;
    void delete_breakpoint(const std::string &id_str);
    void info_registers() const;
    void set_memory(const std::string &addr_str, const std::string &hex_data_str);
    bool is_program_loaded() const { return m_program_loaded; }
    void execute_syscall_command();

private:
    // State variables (previously globals)
    pid_t m_child_pid;
    std::string m_program_name;
    unsigned long long m_entry_point_addr;
    bool m_program_loaded;
    unsigned long long m_current_rip;
    unsigned long long m_program_base_addr;
    bool m_expecting_syscall_exit;           // True if we stopped at syscall entry and next stop should be its exit
    unsigned long long m_traced_syscall_nr;  // To store the syscall number between entry and exit
    unsigned long long m_traced_syscall_rip; // To store RIP of the syscall instruction itself

    std::vector<MemoryRegion> m_executable_regions;

    csh m_capstone_handle;

    struct Breakpoint
    { // Definition here encapsulates it within the Debugger's scope
        int id;
        unsigned long long address;
        uint8_t original_byte;
        bool user_enabled;
        bool currently_in_memory;
        bool is_rva;
        unsigned long long rva_offset;
    };
    std::map<int, Breakpoint> m_active_breakpoints;
    std::map<unsigned long long, int> m_address_to_breakpoint_id;
    int m_next_breakpoint_id; // This will be initialized to 0 for each new Debugger object

    // Private helper methods
    void load_memory_maps();
    bool is_address_in_executable_region(unsigned long long addr) const;
    void enable_breakpoint_in_memory(Breakpoint &bp);
    void disable_breakpoint_in_memory(Breakpoint &bp);
    void disassemble_and_print(unsigned long long rip, int count = 5);
    bool read_memory_byte(unsigned long long addr, uint8_t &value);
    bool write_memory_byte(unsigned long long addr, uint8_t value);
    bool step_over_breakpoint_at_current_rip_if_needed();

    // ELF and ptrace helpers - can take m_child_pid implicitly or explicitly
    unsigned long long get_elf_file_entry_rva(const std::string &prog_path) const;
    unsigned long long get_auxv_val(pid_t cpid, unsigned long long type) const;
    std::string read_string_from_child_mem(pid_t cpid, unsigned long long addr) const;
    unsigned long long get_prog_base_from_maps(pid_t cpid, const std::string &target_prog_name) const;
    bool hex_string_to_bytes(const std::string &hex_str, std::vector<uint8_t> &bytes) const;
    // Utility
    bool parse_hex_address(const std::string &s, unsigned long long &addr) const; // Can be static
};

Debugger::Debugger() : m_child_pid(-1),
                       m_entry_point_addr(0),
                       m_program_loaded(false),
                       m_current_rip(0),
                       m_program_base_addr(0),
                       m_capstone_handle(0), // Or CS_INVALID_HANDLE
                       m_next_breakpoint_id(0),
                       m_expecting_syscall_exit(false),
                       m_traced_syscall_nr(0),
                       m_traced_syscall_rip(0)
{ // Breakpoint IDs start from 0 for each new debugger session/object

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone_handle) != CS_ERR_OK)
    {
        std::cerr << "Failed to initialize Capstone engine." << std::endl;
        // Throw an exception or set an error state that load_program can check
        throw std::runtime_error("Failed to initialize Capstone");
    }
}

Debugger::~Debugger()
{
    if (m_child_pid > 0)
    {
        // Best effort to restore original bytes at breakpoints
        for (auto &pair_id_bp : m_active_breakpoints)
        {
            Breakpoint &bp = pair_id_bp.second;
            if (bp.user_enabled && bp.currently_in_memory)
            {
                // This ptrace might fail if child is already messed up, but try.
                long current_word_val = ptrace(PTRACE_PEEKTEXT, m_child_pid, bp.address, nullptr);
                if (errno == 0)
                {
                    unsigned long original_instruction_word = (current_word_val & ~0xFFULL) | bp.original_byte;
                    ptrace(PTRACE_POKETEXT, m_child_pid, bp.address, (void *)original_instruction_word);
                }
            }
        }
        kill(m_child_pid, SIGKILL);
        waitpid(m_child_pid, nullptr, 0);
    }
    if (m_capstone_handle != 0)
    {
        cs_close(&m_capstone_handle);
    }
}

void Debugger::load_memory_maps()
{
    m_executable_regions.clear();
    if (m_child_pid == -1)
        return;

    std::ifstream maps_file("/proc/" + std::to_string(m_child_pid) + "/maps");
    std::string line;
    while (std::getline(maps_file, line))
    {
        std::stringstream ss(line);
        std::string addr_range, permissions, offset_str, dev_str, inode_str, pathname;

        ss >> addr_range >> permissions >> offset_str >> dev_str >> inode_str;
        std::getline(ss >> std::ws, pathname); // Read pathname carefully

        unsigned long long start_addr, end_addr;
        if (sscanf(addr_range.c_str(), "%llx-%llx", &start_addr, &end_addr) != 2)
        {
            continue;
        }

        if (permissions.find('x') != std::string::npos)
        {
            m_executable_regions.push_back({start_addr, end_addr, permissions, pathname});
        }
    }
}

bool Debugger::is_address_in_executable_region(unsigned long long addr) const
{
    // It's important that load_memory_maps() is called before needing this,
    // or this function could load them on demand if m_executable_regions is empty.
    // For now, relying on calls in disassemble_and_print.
    if (m_executable_regions.empty() && m_child_pid != -1)
    {
        // This can happen if disassemble_and_print hasn't been called yet after loading a program.
        // Or if child is running and maps change.
        // To be safe, can call load_memory_maps() here, but might be a perf hit if called often.
    }

    for (const auto &region : m_executable_regions)
    {
        if (addr >= region.start && addr < region.end)
        {
            return true;
        }
    }
    return false;
}

void Debugger::enable_breakpoint_in_memory(Breakpoint &bp)
{
    if (!m_program_loaded || m_child_pid == -1 || !bp.user_enabled)
    {
        return;
    }
    if (bp.currently_in_memory)
    { // Already 0xCC
        return;
    }

    // The bp.original_byte should have been correctly read by set_breakpoint (or updated by patch)
    if (write_memory_byte(bp.address, 0xCC))
    {
        bp.currently_in_memory = true;
    }
    else
    {
        bp.currently_in_memory = false; // Ensure this reflects failure
    }
}

void Debugger::disable_breakpoint_in_memory(Breakpoint &bp)
{
    if (!m_program_loaded || m_child_pid == -1)
    {
        return;
    }
    // No need to check bp.user_enabled here, this is about memory state.
    if (!bp.currently_in_memory)
    { // Original byte already there or bp not in memory
        return;
    }

    if (write_memory_byte(bp.address, bp.original_byte))
    {
        bp.currently_in_memory = false;
    }
    else
    {
        // If write fails, 0xCC is technically still in memory.
        // bp.currently_in_memory should remain true.
    }
}

void Debugger::disassemble_and_print(unsigned long long rip, int count)
{
    if (m_child_pid == -1 || !m_program_loaded)
    {
        return;
    }

    load_memory_maps(); // Refresh maps

    // Check rip
    if (!is_address_in_executable_region(rip))
    {
        std::cout << "** the address is out of the range of the executable region." << std::endl;
        return;
    }

    std::vector<uint8_t> code_buffer;
    const size_t max_instr_bytes = 15;
    const size_t buffer_prefetch_size = max_instr_bytes * count + max_instr_bytes;
    code_buffer.reserve(buffer_prefetch_size);

    for (size_t i = 0; i < buffer_prefetch_size; ++i)
    {
        unsigned long long current_addr_for_byte = rip + i;
        uint8_t byte_val;

        auto bp_id_iter = m_address_to_breakpoint_id.find(current_addr_for_byte);
        if (bp_id_iter != m_address_to_breakpoint_id.end() &&
            m_active_breakpoints.count(bp_id_iter->second))
        {
            const Breakpoint &bp = m_active_breakpoints.at(bp_id_iter->second);
            if (bp.user_enabled)
            {
                byte_val = bp.original_byte;
            }
            else
            {
                if (!read_memory_byte(current_addr_for_byte, byte_val))
                {
                    break;
                }
            }
        }
        else
        {
            if (!read_memory_byte(current_addr_for_byte, byte_val))
            {
                break;
            }
        }
        code_buffer.push_back(byte_val);
    }

    cs_insn *insn = nullptr;
    size_t disasm_instr_count = 0;
    if (!code_buffer.empty())
    {
        disasm_instr_count = cs_disasm(m_capstone_handle, code_buffer.data(), code_buffer.size(), rip, 0, &insn);
    }

    int instructions_printed = 0;
    bool boundary_message_printed_this_call = false;

    if (disasm_instr_count > 0)
    {
        for (size_t i = 0; i < disasm_instr_count && instructions_printed < count; ++i)
        {
            bool instr_fully_in_exec = true;
            for (unsigned int k = 0; k < insn[i].size; ++k)
            {
                if (!is_address_in_executable_region(insn[i].address + k))
                {
                    instr_fully_in_exec = false;
                    break;
                }
            }

            if (!instr_fully_in_exec)
            {
                if (!boundary_message_printed_this_call)
                {
                    std::cout << "** the address is out of the range of the executable region." << std::endl;
                    boundary_message_printed_this_call = true;
                }
                break;
            }

            std::cout << "      " << std::hex << insn[i].address << ": ";
            std::stringstream bytes_ss;
            for (size_t j = 0; j < insn[i].size; ++j)
            {
                bytes_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(insn[i].bytes[j]) << " ";
            }
            std::cout << std::left << std::setw(30) << bytes_ss.str();
            std::cout << insn[i].mnemonic << "\t" << insn[i].op_str << std::endl;
            instructions_printed++;
        }

        if (!boundary_message_printed_this_call &&      // If not print yet
            instructions_printed < count &&             // Want print
            instructions_printed == disasm_instr_count) // Have reach the print limit, Afterward is invalid
        {
            unsigned long long next_addr_after_capstone_last = insn[disasm_instr_count - 1].address + insn[disasm_instr_count - 1].size;
            if (!is_address_in_executable_region(next_addr_after_capstone_last))
            {
                std::cout << "** the address is out of the range of the executable region." << std::endl;
                boundary_message_printed_this_call = true;
            }
        }
        cs_free(insn, disasm_instr_count);
    }
    else // disasm_instr_count == 0
    {
    }

    std::cout << std::dec;
}

bool Debugger::read_memory_byte(unsigned long long addr, uint8_t &value)
{
    if (m_child_pid <= 0)
    {
        return false;
    }
    std::string mem_path = "/proc/" + std::to_string(m_child_pid) + "/mem";
    // O_SYNC: May not be strictly necessary for read, but doesn't hurt.
    int fd = open(mem_path.c_str(), O_RDONLY | O_SYNC);
    if (fd == -1)
    {
        // Commented out for less verbose default, enable if needed
        return false;
    }
    // Move the fd read ptr to the offset
    if (lseek(fd, static_cast<off_t>(addr), SEEK_SET) == -1)
    {
        // std::cerr << "[DEBUG read_memory_byte] Failed to lseek to 0x" << std::hex << addr << std::dec << " in " << mem_path << ": " << strerror(errno) << std::endl;
        close(fd);
        return false;
    }

    ssize_t bytes_read = ::read(fd, &value, 1); // Use global scope ::read
    close(fd);

    if (bytes_read != 1)
    {
        // std::cerr << "[DEBUG read_memory_byte] Failed to read 1 byte from 0x" << std::hex << addr << std::dec << " in " << mem_path << ". Bytes read: " << bytes_read;
        // if (bytes_read == -1) std::cerr << ", errno: " << strerror(errno);
        // std::cerr << std::endl;
        return false;
    }
    return true;
}

bool Debugger::write_memory_byte(unsigned long long addr, uint8_t value)
{
    if (m_child_pid <= 0)
    {
        std::cerr << "[DEBUG write_memory_byte] Invalid child PID: " << m_child_pid << std::endl;
        return false;
    }
    std::string mem_path = "/proc/" + std::to_string(m_child_pid) + "/mem";
    // O_SYNC: Attempt to ensure data is physically written for consistency,
    // as the target process is stopped.
    int fd = open(mem_path.c_str(), O_WRONLY | O_SYNC);
    if (fd == -1)
    {
        // Commented out for less verbose default, enable if needed
        // std::cerr << "[DEBUG write_memory_byte] Failed to open " << mem_path << " for writing: " << strerror(errno) << " (addr: 0x" << std::hex << addr << " value: 0x" << static_cast<int>(value) << std::dec << ")" << std::endl;
        return false;
    }

    if (lseek(fd, static_cast<off_t>(addr), SEEK_SET) == -1)
    {
        // std::cerr << "[DEBUG write_memory_byte] Failed to lseek to 0x" << std::hex << addr << std::dec << " in " << mem_path << " for writing: " << strerror(errno) << std::endl;
        close(fd);
        return false;
    }

    ssize_t bytes_written = ::write(fd, &value, 1); // Use global scope ::write
    close(fd);

    if (bytes_written != 1)
    {
        // std::cerr << "[DEBUG write_memory_byte] Failed to write 1 byte (0x" << std::hex << static_cast<int>(value) << std::dec << ") to 0x" << std::hex << addr << std::dec << " in " << mem_path << ". Bytes written: " << bytes_written;
        // if (bytes_written == -1) std::cerr << ", errno: " << strerror(errno);
        // std::cerr << std::endl;
        return false;
    }
    return true;
}

bool Debugger::step_over_breakpoint_at_current_rip_if_needed()
{
    if (m_child_pid <= 0 || !m_program_loaded)
    {
        return false;
    }

    auto bp_iter = m_address_to_breakpoint_id.find(m_current_rip);
    if (bp_iter != m_address_to_breakpoint_id.end() && m_active_breakpoints.count(bp_iter->second))
    {
        Breakpoint &bp = m_active_breakpoints.at(bp_iter->second);

        // This function is for when current RIP has an *active 0xCC* that needs to be executed transparently.
        if (bp.user_enabled && bp.currently_in_memory)
        {

            // 1. Restore original byte (disable_breakpoint_in_memory sets bp.currently_in_memory = false)
            disable_breakpoint_in_memory(bp);
            if (bp.currently_in_memory)
            { // Check if disable_breakpoint_in_memory failed to restore
                std::cerr << "[DEBUG step_over_curr_bp] Failed to restore original byte for BP ID " << bp.id
                          << ". Aborting transparent step-over." << std::endl;
                // Attempt to re-enable to maintain intended state, though it's already problematic.
                enable_breakpoint_in_memory(bp);
                return false;
            }

            // 2. Single step the original instruction
            int status_step;
            if (ptrace(PTRACE_SINGLESTEP, m_child_pid, nullptr, nullptr) < 0)
            {
                perror("PTRACE_SINGLESTEP (step_over_curr_bp)");
                // Try to re-arm breakpoint before returning, even if step failed
                enable_breakpoint_in_memory(bp);
                return false;
            }
            waitpid(m_child_pid, &status_step, 0);

            // 3. Update current RIP from registers
            struct user_regs_struct regs_after_step;
            if (ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &regs_after_step) == 0)
            {
                m_current_rip = regs_after_step.rip;
            }
            else
            {
                perror("PTRACE_GETREGS (step_over_curr_bp after step)");
                // m_current_rip might be stale. This is a critical issue if it happens.
            }

            // 4. Re-arm the breakpoint (put 0xCC back)
            // enable_breakpoint_in_memory will set bp.currently_in_memory = true if successful
            enable_breakpoint_in_memory(bp);
            if (!bp.currently_in_memory)
            {
                std::cerr << "[DEBUG step_over_curr_bp] CRITICAL: Failed to re-enable (re-insert 0xCC for) breakpoint ID "
                          << bp.id << " at 0x" << std::hex << bp.address << std::dec << " after step-over. Breakpoint may not function." << std::endl;
            }

            if (WIFEXITED(status_step) || WIFSIGNALED(status_step))
            {
                std::cout << "** the target program terminated (during transparent step-over)." << std::endl;
                m_program_loaded = false;
                m_child_pid = -1; // Further cleanup in destructor or main loop
                m_executable_regions.clear();
                m_active_breakpoints.clear();
                m_address_to_breakpoint_id.clear();
                return true; // Stepped over, but program ended.
            }

            // We expect a SIGTRAP from PTRACE_SINGLESTEP. No special handling here;
            // the caller (si, cont, syscall) will decide further actions.
            return true; // Successfully stepped over the original instruction transparently
        }
    }
    return false; // No active 0xCC breakpoint at current RIP to step over, or it's already handled
}

unsigned long long Debugger::get_elf_file_entry_rva(const std::string &prog_path) const
{
    int fd = open(prog_path.c_str(), O_RDONLY);
    if (fd < 0)
        return 0;
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
    {
        close(fd);
        return 0;
    }
    close(fd);
    return ehdr.e_entry;
}

// Return the elf actual address
unsigned long long Debugger::get_auxv_val(pid_t cpid, unsigned long long type) const
{
    std::ifstream auxv_file("/proc/" + std::to_string(cpid) + "/auxv", std::ios::binary);
    if (!auxv_file)
        return 0;
    Elf64_auxv_t aux_entry;
    while (auxv_file.read(reinterpret_cast<char *>(&aux_entry), sizeof(aux_entry)))
    {
        if (aux_entry.a_type == type)
        {
            return aux_entry.a_un.a_val;
        }
    }
    return 0;
}

// Use the pid and addr, get the abs path
std::string Debugger::read_string_from_child_mem(pid_t cpid, unsigned long long addr) const
{
    std::string result;
    char c;
    unsigned long long current_addr = addr;
    size_t bytes_read_in_word = 0;
    long word = 0; // Initialize word

    while (true)
    {
        if (bytes_read_in_word % sizeof(long) == 0)
        {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, cpid, current_addr, nullptr);
            if (errno != 0)
                break;
            bytes_read_in_word = 0;
        }
        c = ((char *)&word)[bytes_read_in_word];
        if (c == '\0')
            break;
        result += c;
        current_addr++;
        bytes_read_in_word++;
    }
    return result;
}

unsigned long long Debugger::get_prog_base_from_maps(pid_t cpid, const std::string &target_prog_name) const
{
    std::ifstream maps_file("/proc/" + std::to_string(cpid) + "/maps");
    std::string line;

    while (std::getline(maps_file, line))
    {
        std::stringstream ss(line);
        std::string addr_range, permissions, offset_str, dev_str, inode_str, current_pathname;

        ss >> addr_range >> permissions >> offset_str >> dev_str >> inode_str;
        std::getline(ss >> std::ws, current_pathname); // Read rest as pathname

        if (current_pathname.empty() || current_pathname[0] == '[')
        {
            continue;
        }

        unsigned long long file_offset;
        std::stringstream offset_ss_parser(offset_str); // Use a new stringstream for parsing offset
        offset_ss_parser >> std::hex >> file_offset;
        if (offset_ss_parser.fail())
        {
            std::cerr << "[DEBUG] Failed to parse offset: " << offset_str << std::endl;
            continue;
        }

        if (file_offset == 0 && current_pathname == target_prog_name)
        {
            std::string start_addr_str = addr_range.substr(0, addr_range.find('-'));
            unsigned long long start_addr = std::stoull(start_addr_str, nullptr, 16);
            return start_addr;
        }
    }
    std::cerr << "[DEBUG] No match found in get_prog_base_from_maps for: '" << target_prog_name << "'" << std::endl;
    return 0;
}

bool Debugger::parse_hex_address(const std::string &s, unsigned long long &addr) const
{
    if (s.empty())
        return false;
    try
    {
        size_t pos;
        // Use base 16 for all inputs, as "40100d" is also hex per requirement.
        addr = std::stoull(s, &pos, 16);
        return pos == s.length(); // Ensure entire string was parsed
    }
    catch (const std::invalid_argument &ia)
    {
        return false;
    }
    catch (const std::out_of_range &oor)
    {
        return false;
    }
}

void Debugger::info_registers() const
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &regs) == -1)
    {
        perror("ptrace PTRACE_GETREGS");
        std::cout << "** failed to get registers." << std::endl;
        return;
    }

    std::vector<std::pair<std::string, unsigned long long>> registers_to_print = {
        {"rax", regs.rax}, {"rbx", regs.rbx}, {"rcx", regs.rcx}, {"rdx", regs.rdx}, {"rsi", regs.rsi}, {"rdi", regs.rdi}, {"rbp", regs.rbp}, {"rsp", regs.rsp}, {"r8", regs.r8}, {"r9", regs.r9}, {"r10", regs.r10}, {"r11", regs.r11}, {"r12", regs.r12}, {"r13", regs.r13}, {"r14", regs.r14}, {"r15", regs.r15}, {"rip", regs.rip}, {"eflags", regs.eflags}};

    const int regs_per_line = 3;

    // Save original iostream manipulators to restore them later
    std::ios_base::fmtflags original_flags = std::cout.flags();
    char original_fill = std::cout.fill();

    for (size_t i = 0; i < registers_to_print.size(); ++i)
    {
        std::cout << std::left << std::setfill(' ') << std::setw(8)
                  << ("$" + registers_to_print[i].first);

        std::cout << "0x" << std::right << std::hex << std::setfill('0') << std::setw(16)
                  << registers_to_print[i].second;

        std::cout << std::setfill(' ');

        if ((i + 1) % regs_per_line == 0 || i == registers_to_print.size() - 1)
        {
            std::cout << std::endl;
        }
        else
        {
            std::cout << "    "; // Separator for registers on the same line
        }
    }

    std::cout.flags(original_flags);
    std::cout.fill(original_fill);
    std::cout << std::dec;
}

bool Debugger::load_program(const std::string &program_path_arg)
{
    // If this object was somehow reused and had a child, kill it.
    // But the main loop's unique_ptr strategy makes this less likely for load_program.
    if (m_child_pid > 0)
    {
        kill(m_child_pid, SIGKILL);
        waitpid(m_child_pid, nullptr, 0);
        m_child_pid = -1; // Reset pid for the new program
    }
    // Reset other relevant state for a fresh load (maps, rip etc.)
    m_program_loaded = false;
    m_executable_regions.clear();
    m_program_base_addr = 0;
    m_entry_point_addr = 0;
    m_current_rip = 0;
    // m_active_breakpoints and m_address_to_breakpoint_id are already empty for a new object.
    // m_next_breakpoint_id is already 0 for a new object.

    m_program_name = program_path_arg;

    m_child_pid = fork();
    if (m_child_pid == 0)
    { // Child
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        char *const argv_child[] = {const_cast<char *>(m_program_name.c_str()), nullptr};
        execvp(m_program_name.c_str(), argv_child);
        perror("execvp");
        exit(EXIT_FAILURE);
    }
    else if (m_child_pid > 0)
    { // Parent
        int status;
        waitpid(m_child_pid, &status, 0);
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        {
            std::cerr << "** Error: Child process did not stop as expected." << std::endl;
            kill(m_child_pid, SIGKILL);
            waitpid(m_child_pid, nullptr, 0);
            m_child_pid = -1;
            return false;
        }
        // Set (SIGTRAP | 0x80), help for distinguish child syscall
        if (ptrace(PTRACE_SETOPTIONS, m_child_pid, 0, PTRACE_O_TRACESYSGOOD) == -1)
        {
            perror("ptrace PTRACE_SETOPTIONS PTRACE_O_TRACESYSGOOD");
            // Decide if this is a fatal error. For syscall command to work as expected, it's critical.
            // You might choose to return false or print a strong warning.
            std::cerr << "** Warning: Failed to set PTRACE_O_TRACESYSGOOD. Syscall tracing may not work correctly." << std::endl;
        }

        unsigned long long elf_e_entry = get_elf_file_entry_rva(m_program_name); // Uses member function

        // Get the exec elf abs path name
        std::string execfn_path_str;
        unsigned long long at_execfn_addr = get_auxv_val(m_child_pid, AT_EXECFN);
        if (at_execfn_addr != 0)
        {
            execfn_path_str = read_string_from_child_mem(m_child_pid, at_execfn_addr);
        }
        if (execfn_path_str.empty() || execfn_path_str[0] != '/')
        {
            char abs_path_buff[PATH_MAX];
            std::string path_to_resolve = m_program_name;
            if (!execfn_path_str.empty() && execfn_path_str[0] != '/')
                path_to_resolve = execfn_path_str;
            if (realpath(path_to_resolve.c_str(), abs_path_buff) != NULL)
            {
                execfn_path_str = abs_path_buff;
            }
            else
            {
                if (m_program_name[0] == '/')
                    execfn_path_str = m_program_name;
                else
                    execfn_path_str = path_to_resolve;
            }
        }

        m_program_base_addr = get_prog_base_from_maps(m_child_pid, execfn_path_str);
        // Check ELF is PIE?
        Elf64_Ehdr ehdr_check;
        int fd_check = open(execfn_path_str.c_str(), O_RDONLY);
        bool is_pie_type = false;
        if (fd_check >= 0)
        {
            if (read(fd_check, &ehdr_check, sizeof(ehdr_check)) == sizeof(ehdr_check))
            {
                is_pie_type = (ehdr_check.e_type == ET_DYN);
            }
            close(fd_check);
        }
        // Is PIE: Entrypoint = base + entry
        if (is_pie_type)
        {
            // Unused check
            if (m_program_base_addr == 0)
            { // Maps failed for PIE
                unsigned long long at_entry_val_aux = get_auxv_val(m_child_pid, AT_ENTRY);
                if (at_entry_val_aux != 0 && elf_e_entry != 0)
                {
                    m_entry_point_addr = at_entry_val_aux;
                    m_program_base_addr = m_entry_point_addr - elf_e_entry;
                }
                else
                {
                    m_entry_point_addr = elf_e_entry; // Likely wrong, but a fallback
                }
            }
            else
            {
                m_entry_point_addr = m_program_base_addr + elf_e_entry;
            }
        }
        else
        { // Non-PIE
            m_entry_point_addr = elf_e_entry;
        }

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &regs);
        m_current_rip = regs.rip;
        // Check rip addr == entry_point, unused check
        if (m_current_rip != m_entry_point_addr && m_entry_point_addr != 0)
        {
            long temp_orig_byte = ptrace(PTRACE_PEEKTEXT, m_child_pid, m_entry_point_addr, nullptr);
            if (errno == 0)
            {
                unsigned long temp_trap = (temp_orig_byte & ~0xFFULL) | 0xCCULL;
                ptrace(PTRACE_POKETEXT, m_child_pid, m_entry_point_addr, (void *)temp_trap);
                ptrace(PTRACE_CONT, m_child_pid, nullptr, nullptr);
                waitpid(m_child_pid, &status, 0);
                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
                {
                    ptrace(PTRACE_POKETEXT, m_child_pid, m_entry_point_addr, (void *)temp_orig_byte);
                    ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &regs);
                    regs.rip = m_entry_point_addr;
                    ptrace(PTRACE_SETREGS, m_child_pid, nullptr, &regs);
                    m_current_rip = m_entry_point_addr;
                }
                else
                { /* Error stopping at entry */
                    kill(m_child_pid, SIGKILL);
                    waitpid(m_child_pid, nullptr, 0);
                    m_child_pid = -1;
                    return false;
                }
            }
            else
            { /* Error peeking at entry */
                kill(m_child_pid, SIGKILL);
                waitpid(m_child_pid, nullptr, 0);
                m_child_pid = -1;
                return false;
            }
        }
        else if (m_entry_point_addr == 0 && elf_e_entry != 0)
        { // Could not determine entry point for a valid ELF
            std::cerr << "** Error: Could not determine program entry point." << std::endl;
            kill(m_child_pid, SIGKILL);
            waitpid(m_child_pid, nullptr, 0);
            m_child_pid = -1;
            return false;
        }
        else
        {
            m_current_rip = m_entry_point_addr;
        }

        m_program_loaded = true;
        std::cout << "** program '" << program_path_arg << "' loaded. entry point: 0x"
                  << std::hex << m_entry_point_addr << "." << std::dec << std::endl;
        disassemble_and_print(m_current_rip); // Call member function
        return true;
    }
    else
    { // Fork failed
        perror("fork");
        return false;
    }
    return false; // Should not reach here
}

void Debugger::step_instruction()
{
    m_expecting_syscall_exit = false; // Reset syscall state

    bool stepped_over_bp_at_rip = step_over_breakpoint_at_current_rip_if_needed();

    if (!m_program_loaded)
    { // Program might have terminated during the step-over
        return;
    }

    if (stepped_over_bp_at_rip)
    {
        // The original instruction at the breakpoint was executed transparently.
        // m_current_rip is now at the next instruction.
        // The 'si' command's job (execute one instruction) is done.
        // Now, check if this NEW m_current_rip lands on an active breakpoint.

        auto landed_bp_iter = m_address_to_breakpoint_id.find(m_current_rip);
        if (landed_bp_iter != m_address_to_breakpoint_id.end() && m_active_breakpoints.count(landed_bp_iter->second))
        {
            Breakpoint &bp_landed_on = m_active_breakpoints.at(landed_bp_iter->second);
            if (bp_landed_on.user_enabled && bp_landed_on.currently_in_memory)
            { // Hit an active 0xCC
                std::cout << "** hit a breakpoint at 0x" << std::hex << bp_landed_on.address << "." << std::dec << std::endl;
                disable_breakpoint_in_memory(bp_landed_on); // Restore original byte
                // Ensure RIP is set to the start of this newly hit breakpoint
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &regs) == 0)
                {
                    regs.rip = bp_landed_on.address;
                    if (ptrace(PTRACE_SETREGS, m_child_pid, nullptr, &regs) == 0)
                    {
                        m_current_rip = bp_landed_on.address;
                    }
                    else
                    {
                        perror("PTRACE_SETREGS (si after transparent step hit)");
                    }
                }
                else
                {
                    perror("PTRACE_GETREGS (si after transparent step hit)");
                }
            }
        }
        disassemble_and_print(m_current_rip);
        return;
    }

    // --- Standard PTRACE_SINGLESTEP logic (if no transparent step-over occurred) ---
    // This path is taken if:
    // 1. No breakpoint at m_current_rip.
    // 2. Breakpoint at m_current_rip, but original byte is already in memory (bp.currently_in_memory == false),
    //    meaning we are stepping off a previously *handled* breakpoint.
    int status;
    unsigned long long rip_before_standard_step = m_current_rip;
    Breakpoint *bp_being_stepped_off = nullptr;

    auto bp_iter = m_address_to_breakpoint_id.find(rip_before_standard_step);
    if (bp_iter != m_address_to_breakpoint_id.end() && m_active_breakpoints.count(bp_iter->second))
    {
        Breakpoint &bp = m_active_breakpoints.at(bp_iter->second);
        if (bp.user_enabled && !bp.currently_in_memory)
        { // Stepping off a *handled* breakpoint (original byte is there)
            bp_being_stepped_off = &bp;
        }
    }

    if (ptrace(PTRACE_SINGLESTEP, m_child_pid, nullptr, nullptr) < 0)
    {
        perror("ptrace PTRACE_SINGLESTEP (standard si)");
        return;
    }
    waitpid(m_child_pid, &status, 0);

    if (bp_being_stepped_off)
    { // If we stepped off a handled breakpoint, re-arm it with 0xCC.
        enable_breakpoint_in_memory(*bp_being_stepped_off);
    }

    if (WIFEXITED(status) || WIFSIGNALED(status))
    {
        std::cout << "** the target program terminated." << std::endl;
        m_program_loaded = false;
        m_child_pid = -1; /* basic cleanup */
        return;
    }

    if (WIFSTOPPED(status))
    {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &regs) == 0)
        {
            m_current_rip = regs.rip;
        }
        else
        {
            perror("PTRACE_GETREGS (standard si after stop)");
            // m_current_rip might be stale
        }

        auto landed_bp_iter = m_address_to_breakpoint_id.find(m_current_rip);
        if (landed_bp_iter != m_address_to_breakpoint_id.end() && m_active_breakpoints.count(landed_bp_iter->second))
        {
            Breakpoint &bp_landed_on = m_active_breakpoints.at(landed_bp_iter->second);
            // This is a hit on an active 0xCC (not the one we might have just stepped off and re-armed)
            if (bp_landed_on.user_enabled && bp_landed_on.currently_in_memory)
            {
                std::cout << "** hit a breakpoint at 0x" << std::hex << bp_landed_on.address << "." << std::dec << std::endl;
                disable_breakpoint_in_memory(bp_landed_on); // Restore original byte
                // Ensure RIP is at the breakpoint address for consistent state
                regs.rip = bp_landed_on.address;
                if (ptrace(PTRACE_SETREGS, m_child_pid, nullptr, &regs) == 0)
                {
                    // Actually, it's already the same.
                    m_current_rip = bp_landed_on.address;
                }
                else
                {
                    perror("PTRACE_SETREGS (standard si landed on bp)");
                }
            }
        }
        disassemble_and_print(m_current_rip);
    }
}

void Debugger::continue_execution()
{
    m_expecting_syscall_exit = false;

    bool stepped_over_bp_at_rip = step_over_breakpoint_at_current_rip_if_needed();

    if (!m_program_loaded)
    { // Program might have terminated
        return;
    }

    // If stepped_over_bp_at_rip is true, m_current_rip is updated, and the BP is re-armed.
    // We now proceed to PTRACE_CONT from this new m_current_rip.
    // The original 'cont' pre-step (for !bp.currently_in_memory) is still needed if step_over_bp_at_rip was false.

    if (!stepped_over_bp_at_rip)
    {
        // This is the logic for when `cont` is called and RIP is on a *handled* breakpoint
        // (original byte is in memory, so !bp.currently_in_memory).
        auto bp_iter_cont = m_address_to_breakpoint_id.find(m_current_rip);
        if (bp_iter_cont != m_address_to_breakpoint_id.end() &&
            m_active_breakpoints.count(bp_iter_cont->second))
        {
            Breakpoint &bp_at_rip = m_active_breakpoints.at(bp_iter_cont->second);
            if (bp_at_rip.user_enabled && !bp_at_rip.currently_in_memory)
            {
                int status_step_off;
                if (ptrace(PTRACE_SINGLESTEP, m_child_pid, nullptr, nullptr) < 0)
                {
                    perror("PTRACE_SINGLESTEP (cont step-off)");
                    return;
                }
                waitpid(m_child_pid, &status_step_off, 0);

                if (WIFEXITED(status_step_off) || WIFSIGNALED(status_step_off))
                {
                    std::cout << "** the target program terminated." << std::endl;
                    m_program_loaded = false;
                    m_child_pid = -1;
                    return;
                }
                // We expect SIGTRAP from single step. If not, it's an issue.
                if (!WIFSTOPPED(status_step_off) || WSTOPSIG(status_step_off) != SIGTRAP)
                {
                    std::cerr << "[DEBUG cont] Unexpected stop status after PTRACE_SINGLESTEP (cont step-off). Signal: " << WSTOPSIG(status_step_off) << std::endl;
                    // Update RIP and disassemble, then return to let user decide.
                    struct user_regs_struct temp_regs;
                    ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &temp_regs);
                    m_current_rip = temp_regs.rip;
                    disassemble_and_print(m_current_rip);
                    return;
                }

                struct user_regs_struct regs_after_step;
                if (ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &regs_after_step) == 0)
                {
                    m_current_rip = regs_after_step.rip;
                }
                else
                {
                    perror("PTRACE_GETREGS (cont step-off)");
                }

                enable_breakpoint_in_memory(bp_at_rip); // Re-arm the BP we just stepped off
            }
        }
    }

    int status_cont;
    if (ptrace(PTRACE_CONT, m_child_pid, nullptr, nullptr) < 0)
    {
        perror("ptrace PTRACE_CONT");
        return;
    }
    waitpid(m_child_pid, &status_cont, 0);

    if (WIFEXITED(status_cont) || WIFSIGNALED(status_cont))
    {
        std::cout << "** the target program terminated." << std::endl;
        m_program_loaded = false;
        m_child_pid = -1;
        return;
    }

    if (WIFSTOPPED(status_cont))
    {
        struct user_regs_struct regs_stop;
        if (ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &regs_stop) != 0)
        {
            perror("PTRACE_GETREGS (cont after stop)");
            // Fallback: m_current_rip might not be updated accurately.
        }
        unsigned long long rip_at_stop = regs_stop.rip;

        if (WSTOPSIG(status_cont) == SIGTRAP)
        {
            // SIGTRAP could be from a breakpoint (0xCC)
            // RIP after 0xCC trap is typically RIP_OF_CC + 1
            unsigned long long potential_bp_address = rip_at_stop - 1;
            auto hit_bp_iter = m_address_to_breakpoint_id.find(potential_bp_address);

            if (hit_bp_iter != m_address_to_breakpoint_id.end() &&
                m_active_breakpoints.count(hit_bp_iter->second))
            {
                Breakpoint &bp_hit = m_active_breakpoints.at(hit_bp_iter->second);
                if (bp_hit.user_enabled && bp_hit.currently_in_memory)
                { // Hit an active (0xCC) breakpoint
                    std::cout << "** hit a breakpoint at 0x" << std::hex << bp_hit.address << "." << std::dec << std::endl;

                    disable_breakpoint_in_memory(bp_hit); // Restore original byte

                    // Set RIP back to the actual breakpoint instruction address
                    regs_stop.rip = bp_hit.address;
                    if (ptrace(PTRACE_SETREGS, m_child_pid, nullptr, &regs_stop) == 0)
                    {
                        m_current_rip = bp_hit.address;
                    }
                    else
                    {
                        perror("PTRACE_SETREGS (cont hit bp)");
                        m_current_rip = bp_hit.address; // Assume it worked for internal state
                    }
                    disassemble_and_print(m_current_rip);
                    return; // Stop processing, user will issue next command
                }
            }
        }
        // If not a SIGTRAP from our handled breakpoint, or other signal
        m_current_rip = rip_at_stop; // Default update
        disassemble_and_print(m_current_rip);
    }
}

void Debugger::set_breakpoint(const std::string &val_str, bool is_rva_cmd)
{
    unsigned long long input_val;
    if (!parse_hex_address(val_str, input_val))
    {
        std::cout << "** the target address is not valid (format error)." << std::endl;
        return;
    }

    unsigned long long target_address;
    if (is_rva_cmd)
    {
        target_address = m_program_base_addr + input_val;
    }
    else
    {
        target_address = input_val;
    }

    if (m_child_pid <= 0)
    {
        std::cout << "** the target address is not valid (no process)." << std::endl;
        return;
    }

    uint8_t original_byte_val;
    if (!read_memory_byte(target_address, original_byte_val))
    {
        std::cout << "** the target address is not valid (cannot read original byte)." << std::endl;
        return;
    }

    // Handle case where what we read is 0xCC due to an existing active breakpoint.
    // We need its *actual* original byte.
    if (m_address_to_breakpoint_id.count(target_address))
    {
        int existing_bp_id = m_address_to_breakpoint_id.at(target_address);
        if (m_active_breakpoints.count(existing_bp_id))
        {
            Breakpoint &existing_bp = m_active_breakpoints.at(existing_bp_id);
            // If the byte we just read is 0xCC AND that existing breakpoint is marked as 'in memory'
            if (original_byte_val == 0xCC && existing_bp.user_enabled && existing_bp.currently_in_memory)
            {
                original_byte_val = existing_bp.original_byte; // Use the stored true original byte
            }
            // If existing_bp.original_byte was already what we read, that's fine.
        }
    }

    int new_id = m_next_breakpoint_id++;
    Breakpoint bp;
    bp.id = new_id;
    bp.address = target_address;
    bp.original_byte = original_byte_val;
    bp.user_enabled = true;
    bp.currently_in_memory = false;
    bp.is_rva = is_rva_cmd;
    bp.rva_offset = is_rva_cmd ? input_val : 0;

    m_active_breakpoints[new_id] = bp;
    // Handle same break set in same address
    if (!m_address_to_breakpoint_id.count(target_address))
    {
        m_address_to_breakpoint_id[target_address] = new_id;
    }

    enable_breakpoint_in_memory(m_active_breakpoints.at(new_id)); // Uses reference

    // Check if enable_breakpoint_in_memory actually set bp.currently_in_memory to true
    if (m_active_breakpoints.at(new_id).currently_in_memory)
    {
        std::cout << "** set a breakpoint at 0x" << std::hex << target_address << "." << std::dec << std::endl;
    }
    else
    {
        std::cout << "** failed to set breakpoint at 0x" << std::hex << target_address << " (could not write 0xCC)." << std::dec << std::endl;
        // Clean up the breakpoint we just tried to add if enabling it in memory failed.
        m_active_breakpoints.erase(new_id);
        // Potentially clean up m_address_to_breakpoint_id if this was the only ID for that address
        if (m_address_to_breakpoint_id.count(target_address) && m_address_to_breakpoint_id[target_address] == new_id)
        {
            m_address_to_breakpoint_id.erase(target_address);
        }
        // No, don't decrement m_next_breakpoint_id, as IDs should be unique.
    }
}

void Debugger::info_breakpoints() const
{
    bool found_active = false;
    for (const auto &pair : m_active_breakpoints)
    {
        const Breakpoint &bp = pair.second;
        if (bp.user_enabled)
        { // Check if user considers it active
            if (!found_active)
            {
                std::cout << "Num     Address" << std::endl;
                found_active = true;
            }
            std::cout << std::left << std::setw(8) << bp.id
                      << "0x" << std::hex << bp.address << std::dec << std::endl;
        }
    }
    if (!found_active)
    {
        std::cout << "** no breakpoints." << std::endl;
    }
}

void Debugger::delete_breakpoint(const std::string &id_str)
{
    if (!m_program_loaded && m_active_breakpoints.empty())
    {
        std::cout << "** breakpoint " << id_str << " does not exist." << std::endl; // Or no program loaded
        return;
    }
    int id_to_delete;
    try
    {
        id_to_delete = std::stoi(id_str);
    }
    catch (...)
    {
        std::cout << "** breakpoint " << id_str << " does not exist (invalid ID format)." << std::endl;
        return;
    }

    auto bp_iter = m_active_breakpoints.find(id_to_delete);
    if (bp_iter == m_active_breakpoints.end() || !bp_iter->second.user_enabled)
    {
        std::cout << "** breakpoint " << id_to_delete << " does not exist." << std::endl;
        return;
    }

    Breakpoint &bp_to_delete = bp_iter->second;

    // Check if any OTHER user-enabled breakpoint shares this address
    bool other_bp_at_same_address = false;
    for (const auto &pair : m_active_breakpoints)
    {
        if (pair.first != bp_to_delete.id && pair.second.user_enabled && pair.second.address == bp_to_delete.address)
        {
            other_bp_at_same_address = true;
            break;
        }
    }

    if (!other_bp_at_same_address)
    { // Only disable from memory if no other BP needs the 0xCC here
        if (bp_to_delete.currently_in_memory)
        {
            disable_breakpoint_in_memory(bp_to_delete); // Restore original byte
        }
        m_address_to_breakpoint_id.erase(bp_to_delete.address);
    }
    else
    {
        // Another breakpoint is at the same address. Keep the 0xCC (if it was there)
        // and let the other breakpoint manage it.
        // The m_address_to_breakpoint_id might need to be updated if the deleted one was the representative.
        // Find another active bp at that address and point m_address_to_breakpoint_id to it.
        bool remapped = false;
        if (m_address_to_breakpoint_id.count(bp_to_delete.address) && m_address_to_breakpoint_id[bp_to_delete.address] == bp_to_delete.id)
        {
            m_address_to_breakpoint_id.erase(bp_to_delete.address); // Temporarily remove
            for (const auto &pair : m_active_breakpoints)
            {
                if (pair.first != bp_to_delete.id && pair.second.user_enabled && pair.second.address == bp_to_delete.address)
                {
                    m_address_to_breakpoint_id[bp_to_delete.address] = pair.first;
                    remapped = true;
                    break;
                }
            }
        }
    }

    m_active_breakpoints.erase(bp_iter); // Remove from the map by ID

    std::cout << "** delete breakpoint " << id_to_delete << "." << std::endl;
}

bool Debugger::hex_string_to_bytes(const std::string &hex_str, std::vector<uint8_t> &bytes) const
{
    if (hex_str.length() % 2 != 0)
    {
        return false; // Should be handled by caller based on problem spec
    }
    // Max length check should be done by caller as well.
    bytes.clear();
    bytes.reserve(hex_str.length() / 2);

    for (size_t i = 0; i < hex_str.length(); i += 2)
    {
        std::string byte_str = hex_str.substr(i, 2);
        try
        {
            unsigned long byte_val = std::stoul(byte_str, nullptr, 16);
            // stoul with base 16 handles "FF", "ff", etc.
            // No need to check > 0xFF as stoul on 2 hex chars won't exceed it.
            bytes.push_back(static_cast<uint8_t>(byte_val));
        }
        catch (const std::invalid_argument &)
        {
            return false; // Not a valid hex character pair
        }
        catch (const std::out_of_range &)
        {
            return false; // Should not happen for 2 hex chars
        }
    }
    return true;
}

void Debugger::set_memory(const std::string &addr_str, const std::string &hex_data_str)
{
    unsigned long long patch_address;
    if (!parse_hex_address(addr_str, patch_address))
    {
        std::cout << "** the target address is not valid (format error)." << std::endl;
        return;
    }

    if (hex_data_str.length() > 2048 || hex_data_str.length() % 2 != 0)
    {
        std::cout << "** hex string invalid (length constraints: <=2048 and even)." << std::endl;
        return;
    }
    if (hex_data_str.empty())
    {
        std::cout << "** patch memory at 0x" << std::hex << patch_address << "." << std::dec << std::endl;
        return;
    }

    std::vector<uint8_t> bytes_to_write;
    if (!hex_string_to_bytes(hex_data_str, bytes_to_write))
    {
        std::cout << "** hex string invalid (contains non-hex characters)." << std::endl;
        return;
    }

    for (size_t i = 0; i < bytes_to_write.size(); ++i)
    {
        unsigned long long current_addr_to_patch = patch_address + i;
        uint8_t byte_to_write = bytes_to_write[i];

        if (!write_memory_byte(current_addr_to_patch, byte_to_write))
        {
            std::cout << "** the target address is not valid (cannot write for patch at 0x"
                      << std::hex << current_addr_to_patch << ")." << std::dec << std::endl;
            return;
        }

        auto bp_id_iter = m_address_to_breakpoint_id.find(current_addr_to_patch);
        if (bp_id_iter != m_address_to_breakpoint_id.end() &&
            m_active_breakpoints.count(bp_id_iter->second))
        {
            Breakpoint &bp = m_active_breakpoints.at(bp_id_iter->second);
            if (bp.user_enabled)
            {

                bool was_bp_in_memory = bp.currently_in_memory;
                bp.original_byte = byte_to_write; // The "original" under the 0xCC is now the patched byte.

                if (was_bp_in_memory)
                {
                    // The patch overwrote the 0xCC. We need to put 0xCC back.
                    // The bp.original_byte is now correctly set to the patched value.
                    if (!write_memory_byte(bp.address, 0xCC))
                    {
                        std::cerr << "[DEBUG set_memory] Failed to re-insert 0xCC for breakpoint ID " << bp.id << " at 0x" << std::hex << bp.address << std::dec << "." << std::endl;
                        bp.currently_in_memory = false; // 0xCC not there anymore
                    }
                    else
                    {
                        bp.currently_in_memory = true; // 0xCC successfully re-inserted
                    }
                }
            }
        }
    }
    std::cout << "** patch memory at 0x" << std::hex << patch_address << "." << std::dec << std::endl;
}

void Debugger::execute_syscall_command()
{
    bool stepped_over_bp_at_rip = step_over_breakpoint_at_current_rip_if_needed();

    if (!m_program_loaded)
    { // Program might have terminated
        return;
    }

    if (!stepped_over_bp_at_rip)
    {
        // Logic for stepping off a *handled* breakpoint (original byte in memory)
        auto bp_iter_syscall = m_address_to_breakpoint_id.find(m_current_rip);
        if (bp_iter_syscall != m_address_to_breakpoint_id.end() &&
            m_active_breakpoints.count(bp_iter_syscall->second))
        {
            Breakpoint &bp_at_rip = m_active_breakpoints.at(bp_iter_syscall->second);
            if (bp_at_rip.user_enabled && !bp_at_rip.currently_in_memory)
            {
                int status_step_off;
                if (ptrace(PTRACE_SINGLESTEP, m_child_pid, nullptr, nullptr) < 0)
                { /* perror, return */
                }
                waitpid(m_child_pid, &status_step_off, 0);
                if (WIFEXITED(status_step_off) || WIFSIGNALED(status_step_off))
                { /* terminated, return */
                }
                if (!WIFSTOPPED(status_step_off) || WSTOPSIG(status_step_off) != SIGTRAP)
                { /* error, return */
                }

                struct user_regs_struct regs_after_step;
                if (ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &regs_after_step) == 0)
                {
                    m_current_rip = regs_after_step.rip;
                }
                enable_breakpoint_in_memory(bp_at_rip); // Re-arm
            }
        }
    }

    int status_syscall;
    if (ptrace(PTRACE_SYSCALL, m_child_pid, nullptr, nullptr) < 0)
    {
        perror("ptrace PTRACE_SYSCALL");
        return;
    }
    waitpid(m_child_pid, &status_syscall, 0);

    if (WIFEXITED(status_syscall) || WIFSIGNALED(status_syscall))
    {
        std::cout << "** the target program terminated." << std::endl;
        m_program_loaded = false;
        m_child_pid = -1;
        return;
    }

    if (WIFSTOPPED(status_syscall))
    {
        struct user_regs_struct regs_stop;
        if (ptrace(PTRACE_GETREGS, m_child_pid, nullptr, &regs_stop) != 0)
        {
            perror("PTRACE_GETREGS (syscall_cmd after stop)");
        }
        unsigned long long rip_at_stop_syscall = regs_stop.rip;
        int sig = WSTOPSIG(status_syscall);

        if (sig == (SIGTRAP | 0x80))
        { // Syscall-enter or Syscall-exit (PTRACE_O_TRACESYSGOOD)
            if (!m_expecting_syscall_exit)
            { // Syscall Entry
                m_traced_syscall_nr = regs_stop.orig_rax;
                // For syscall instruction (e.g., 'syscall' 0F 05 is 2 bytes), kernel reports RIP *after* it.
                m_traced_syscall_rip = rip_at_stop_syscall - 2; // Assuming syscall instruction is 2 bytes
                m_current_rip = m_traced_syscall_rip;           // For disassembling the syscall instruction itself

                std::cout << "** enter a syscall(" << m_traced_syscall_nr << ") at 0x"
                          << std::hex << m_traced_syscall_rip << "." << std::dec << std::endl;
                m_expecting_syscall_exit = true;
            }
            else
            { // Syscall Exit
                long long syscall_ret_val = static_cast<long long>(regs_stop.rax);
                // m_traced_syscall_rip still holds the address of the syscall instruction.
                // rip_at_stop_syscall is where execution will resume in user mode.
                m_current_rip = rip_at_stop_syscall; // Update m_current_rip for debugger's state for next command.
                                                     // Disassembly should still be from syscall instruction's location.
                std::cout << "** leave a syscall(" << m_traced_syscall_nr << ") = "
                          << syscall_ret_val << " at 0x"
                          << std::hex << m_traced_syscall_rip << "." << std::dec << std::endl;
                m_expecting_syscall_exit = false;
                // For disassembly, show the syscall instruction itself
                disassemble_and_print(m_traced_syscall_rip);
                return; // Return after syscall exit message
            }
        }
        else if (sig == SIGTRAP)
        { // Normal SIGTRAP, could be a breakpoint
            unsigned long long potential_bp_address = rip_at_stop_syscall - 1;
            auto hit_bp_iter = m_address_to_breakpoint_id.find(potential_bp_address);
            if (hit_bp_iter != m_address_to_breakpoint_id.end() &&
                m_active_breakpoints.count(hit_bp_iter->second))
            {
                Breakpoint &bp_hit = m_active_breakpoints.at(hit_bp_iter->second);
                if (bp_hit.user_enabled && bp_hit.currently_in_memory)
                {
                    std::cout << "** hit a breakpoint at 0x" << std::hex << bp_hit.address << "." << std::dec << std::endl;

                    disable_breakpoint_in_memory(bp_hit);
                    regs_stop.rip = bp_hit.address;
                    if (ptrace(PTRACE_SETREGS, m_child_pid, nullptr, &regs_stop) == 0)
                    {
                        m_current_rip = bp_hit.address;
                    }
                    else
                    {
                        perror("PTRACE_SETREGS (syscall_cmd hit bp)");
                        m_current_rip = bp_hit.address;
                    }
                    m_expecting_syscall_exit = false; // Cancel any pending syscall exit expectation
                    disassemble_and_print(m_current_rip);
                    return;
                }
            }
            // If SIGTRAP was not our breakpoint, treat as normal stop
            m_current_rip = rip_at_stop_syscall;
        }
        else
        { // Other signal
            // std::cout << "** stopped by signal " << sig << " at 0x" << std::hex << rip_at_stop_syscall << std::dec << std::endl;
            m_current_rip = rip_at_stop_syscall;
        }
        disassemble_and_print(m_current_rip);
    }
}

int main(int argc, char *argv_main[])
{
    // Capstone is initialized by Debugger constructor now.
    // No global m_capstone_handle needed.

    std::unique_ptr<Debugger> debugger_instance;

    if (argc > 1)
    {
        try
        {
            debugger_instance = std::make_unique<Debugger>();
            if (!debugger_instance->load_program(argv_main[1]))
            {
                debugger_instance.reset(); // Load failed
            }
        }
        catch (const std::runtime_error &e)
        {
            std::cerr << "** Error initializing debugger: " << e.what() << std::endl;
            return 1;
        }
    }

    std::string line_input;
    while (true)
    {
        print_prompt();
        if (!std::getline(std::cin, line_input))
        {
            if (std::cin.eof())
            {
                // Destructor of debugger_instance will handle child cleanup
                std::cout << std::endl;
                break;
            }
            std::cin.clear();
            continue;
        }

        if (line_input.empty())
            continue;

        std::stringstream ss(line_input);
        std::string command;
        std::string arg1;
        ss >> command;
        if (!(ss >> arg1))
            arg1 = ""; // Ensure arg1 is empty if not provided

        if (command == "load")
        {
            if (!arg1.empty())
            {
                try
                {
                    debugger_instance.reset(); // Explicitly destroy old instance first
                    debugger_instance = std::make_unique<Debugger>();
                    if (!debugger_instance->load_program(arg1))
                    {
                        debugger_instance.reset(); // Load failed
                    }
                }
                catch (const std::runtime_error &e)
                {
                    std::cerr << "** Error initializing debugger for new program: " << e.what() << std::endl;
                    debugger_instance.reset();
                }
            }
            else
            {
                std::cout << "** usage: load <program_path>" << std::endl;
            }
        }
        else if (command == "exit" || command == "q")
        {
            // Destructor of debugger_instance will handle child cleanup
            break;
        }
        // For commands requiring a loaded program:
        else if (command == "si" || command == "s")
        {
            if (debugger_instance && debugger_instance->is_program_loaded())
            {
                debugger_instance->step_instruction();
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if (command == "cont" || command == "c")
        {
            if (debugger_instance && debugger_instance->is_program_loaded())
            {
                debugger_instance->continue_execution();
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if (command == "break" || command == "b")
        {
            if (debugger_instance && debugger_instance->is_program_loaded())
            {
                if (!arg1.empty())
                    debugger_instance->set_breakpoint(arg1, false);
                else
                    std::cout << "** usage: break <hex address>" << std::endl;
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if (command == "breakrva" || command == "br")
        {
            if (debugger_instance && debugger_instance->is_program_loaded())
            {
                if (!arg1.empty())
                    debugger_instance->set_breakpoint(arg1, true);
                else
                    std::cout << "** usage: breakrva <hex offset>" << std::endl;
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        else if (command == "info")
        {
            if (arg1 == "reg" || arg1 == "r")
            {
                if (debugger_instance && debugger_instance->is_program_loaded())
                {
                    debugger_instance->info_registers();
                }
                else
                {
                    std::cout << "** please load a program first." << std::endl;
                }
            }
            else if (arg1 == "break" || arg1 == "b" || arg1 == "breakpoints")
            {
                // info break can be shown even if program not loaded, it will show "no breakpoints"
                // or it can be restricted too. For now, let's allow it.
                if (debugger_instance)
                    debugger_instance->info_breakpoints();
                else
                    std::cout << "** no breakpoints (no debugger instance)." << std::endl; // Or handled by info_breakpoints itself
            }
            else if (arg1.empty())
            {
                std::cout << "** usage: info <type (e.g. reg, break)>" << std::endl;
            }
            else
            {
                std::cout << "** unknown info command: " << arg1 << std::endl;
            }
        }
        else if (command == "delete" || command == "d")
        {
            if (debugger_instance && debugger_instance->is_program_loaded())
            { // Deleting needs a context
                if (!arg1.empty())
                    debugger_instance->delete_breakpoint(arg1);
                else
                    std::cout << "** usage: delete <breakpoint_id>" << std::endl;
            }
            else
            {
                std::cout << "** please load a program first (or no breakpoints to delete)." << std::endl;
            }
        }
        else if (command == "patch")
        {
            std::string data_hex_str;
            if (arg1.length() && ss >> data_hex_str)
            { // Expecting two arguments
                if (debugger_instance && debugger_instance->is_program_loaded())
                {
                    debugger_instance->set_memory(arg1, data_hex_str);
                }
                else
                {
                    std::cout << "** please load a program first." << std::endl;
                }
            }
            else
            {
                std::cout << "** usage: patch <hex address> <hex string>" << std::endl;
            }
        }
        else if (command == "syscall" || command == "sc")
        { // Added "sc" as shortcut
            if (debugger_instance && debugger_instance->is_program_loaded())
            {
                debugger_instance->execute_syscall_command();
            }
            else
            {
                std::cout << "** please load a program first." << std::endl;
            }
        }
        // ... other commands
        else
        {
            if (!command.empty())
            { // Avoid printing for empty line after prompt
                std::cout << "** unknown command: " << command << std::endl;
            }
        }
    }
    // debugger_instance goes out of scope here, its destructor is called.
    return 0;
}
