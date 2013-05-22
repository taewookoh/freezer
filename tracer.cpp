#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/reg.h>

static unsigned char org_inst;

void setup_bp(int pid, unsigned long bp, unsigned long after_bp, unsigned long after_bp_addr, unsigned long org_inst_addr)
{
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, 0, &regs);
  printf("rip: %lx\n", regs.rip);

  uint64_t code = ptrace(PTRACE_PEEKTEXT, pid, bp, 0);
  uint64_t new_code = (code & 0xFFFFFFFFFFFFFF00L) | 0xcc;
  ptrace(PTRACE_POKEDATA, pid, bp, new_code);
  uint64_t confirm_code = ptrace(PTRACE_PEEKTEXT, pid, bp, 0);
  printf("code: %x -> %x\n", code & 0xff, confirm_code & 0xff);

  org_inst = code & 0xff;

  uint64_t data = ptrace(PTRACE_PEEKDATA, pid, org_inst_addr, 0);
  uint64_t new_data = (data & 0xFFFFFFFFFFFFFF00L) | ( (uint64_t)org_inst );
  ptrace(PTRACE_POKEDATA, pid, org_inst_addr, new_data);
  uint64_t confirm_data = ptrace(PTRACE_PEEKDATA, pid, org_inst_addr, 0);
  printf("data: %x -> %x\n", data & 0xff, confirm_data & 0xff);

  // put after bp
  ptrace(PTRACE_POKEDATA, pid, after_bp_addr, after_bp);
}

void suppress_bp(int pid, unsigned long bp)
{
  uint64_t code = ptrace(PTRACE_PEEKTEXT, pid, bp, 0);
  uint64_t new_code = (code & 0xFFFFFFFFFFFFFF00L) | org_inst;
  ptrace(PTRACE_POKEDATA, pid, bp, new_code);
  uint64_t confirm_code = ptrace(PTRACE_PEEKTEXT, pid, bp, 0);
  printf("suppress, code: %x -> %x\n", code & 0xff, confirm_code & 0xff);

  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, 0, &regs);
  printf("suppress, rip: %lx\n", regs.rip);

  // roll back one instruction?
  regs.rip -= 1;
  ptrace(PTRACE_SETREGS, pid, 0, &regs);
}

int main(int argc, char** argv)
{
  int pid;

  unsigned long bp = strtol(argv[1], NULL, 0);
  unsigned long after_bp = strtol(argv[2], NULL, 0);
  unsigned long after_bp_addr = strtol(argv[3], NULL, 0);
  unsigned long org_inst_addr = strtol(argv[4], NULL, 0);

  if ((pid = fork()) == -1)
  {
    perror("fork");
    exit(1);
  }

  if (pid == 0)
  {
    ptrace(PTRACE_TRACEME,0,0,0);
    execv("./target",0);
    perror("execv");
    exit(1);
  }
  else
  {
    int status;
    int init = 0;
    while(1)
    {
      wait(&status);

      if (WIFEXITED(status))
      {
        printf("target exited\n");
        break;
      }
      else if (WIFSTOPPED(status))
      {
        printf("signal: %s\n", strsignal(WSTOPSIG(status)));
        if ( WSTOPSIG(status) == SIGTRAP )
        {
          if (!init)
          {
            init = 1;
            setup_bp(pid, bp, after_bp, after_bp_addr, org_inst_addr);
            //ptrace(PTRACE_CONT,pid,0,0);
            ptrace(PTRACE_DETACH,pid,0,0);
          }
          else
          {
            // this should be called only after reattachment

            // suppress breakpoint
            suppress_bp(pid, bp);

            //ptrace(PTRACE_CONT,pid,0,SIGTRAP);
            ptrace(PTRACE_CONT,pid,0,0);
          }
        }
        else
          ptrace(PTRACE_CONT,pid,0,WSTOPSIG(status));
      }
      else
      {
        printf("signum: %d\n", WSTOPSIG(status));
        perror("!WIFEXITED && !WIFSTOPPED");
        exit(1);
      }
    }
  }

}
