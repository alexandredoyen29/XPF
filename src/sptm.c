#import "sptm.h"
#import "xpf.h"
#include <choma/arm64.h>
#include <choma/PatchFinder.h>

static uint64_t xpf_find_pmap_enter_pv(void)
{
  PFStringMetric *stringMetric = pfmetric_string_init("pmap_enter_pv");
  __block uint64_t pmap_enter_pv_stringAddr = 0;
  pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
    pmap_enter_pv_stringAddr = vmaddr;
    *stop = true;
  });
  pfmetric_free(stringMetric);

  PFXrefMetric *xrefMetric = pfmetric_xref_init(pmap_enter_pv_stringAddr, XREF_TYPE_MASK_REFERENCE);
  __block uint64_t pmap_enter_pv = 0;
  pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
    pmap_enter_pv = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
    *stop = true;
  });
  pfmetric_free(xrefMetric);

  return pmap_enter_pv;
}

static uint64_t xpf_find_pv_head_table(void)
{
  uint64_t pmap_enter_pv = xpf_item_resolve("kernelSymbol.pmap_enter_pv");
  printf("pmap_enter_pv: 0x%016llX\n", pmap_enter_pv);

  uint32_t ldrAnyInst = 0, ldrAnyMask = 0;
  arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAnyInst, &ldrAnyMask);

  uint64_t ref = pfsec_find_next_inst(gXPF.kernelTextSection, pmap_enter_pv, 0, ldrAnyInst, ldrAnyMask);
  return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, ref);
}

void xpf_sptm_init(void) {
  if (gXPF.kernelIsSptm) {
    xpf_item_register("kernelSymbol.pmap_enter_pv", xpf_find_pmap_enter_pv, NULL);
    xpf_item_register("kernelSymbol.pv_head_table", xpf_find_pv_head_table, NULL);
  }
}