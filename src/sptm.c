#import "sptm.h"
#import "xpf.h"
#include <choma/arm64.h>
#include <choma/PatchFinder.h>

static uint64_t xpf_find_pmap_data_bootstrap(void)
{
  uint32_t addXAnyXAny30LSL12Inst = 0x9140C000, addXAnyXAny30LSL12Mask = 0xFFFFF000;
  uint64_t addAddr = pfsec_find_next_inst(gXPF.kernelTextSection, gXPF.kernelTextSection->vmaddr, 0, addXAnyXAny30LSL12Inst, addXAnyXAny30LSL12Mask);
  if(addAddr) {
    return pfsec_find_function_start(gXPF.kernelTextSection, addAddr);
  }
  return 0;
}

static uint64_t xpf_find_pv_head_table(void)
{
  uint64_t pmap_data_bootstrapAddr = xpf_item_resolve("kernelSymbol.pmap_data_bootstrap");
  uint32_t bcsAnyInst = 0, bcsAnyMask = 0;
  arm64_gen_b_c_cond(OPT_BOOL(false), OPT_UINT64_NONE, OPT_UINT64_NONE, ARM64_COND(2), &bcsAnyInst, &bcsAnyMask);
  uint64_t bcsAddr = pfsec_find_next_inst(gXPF.kernelTextSection, pmap_data_bootstrapAddr, 0, bcsAnyInst, bcsAnyMask);
  uint32_t adrpAnyInst = 0, adprAnyMask = 0;
  arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, ARM64_REG_ANY, &adrpAnyInst, &adprAnyMask);
  uint64_t adrpAddr = pfsec_find_prev_inst(gXPF.kernelTextSection, bcsAddr, 0, adrpAnyInst, adprAnyMask);
  if(adrpAddr) {
    uint64_t tmpImm = 0;
    uint64_t tmpImm2 = 0;
    arm64_dec_adr_p(pfsec_read32(gXPF.kernelTextSection, adrpAddr), adrpAddr, &tmpImm, NULL, NULL);
    arm64_dec_str_imm(pfsec_read32(gXPF.kernelTextSection, adrpAddr + 4), NULL, NULL, &tmpImm2, NULL, NULL);
    if(tmpImm && tmpImm2) {
      uint64_t pv_head_tableAddr = tmpImm + tmpImm2;
      return pv_head_tableAddr;
    }
  }
  return 0;
}

void xpf_sptm_init(void) {
  if (gXPF.kernelIsSptm) {
    xpf_item_register("kernelSymbol.pmap_data_bootstrap", xpf_find_pmap_data_bootstrap, NULL);
    xpf_item_register("kernelSymbol.pv_head_table", xpf_find_pv_head_table, NULL);
  }
}