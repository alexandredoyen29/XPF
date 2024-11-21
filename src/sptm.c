#import "sptm.h"
#import "xpf.h"
#include <choma/arm64.h>
#include <choma/PatchFinder.h>

void xpf_sptm_init(void) {
  if (gXPF.kernelIsSptm) {
//    xpf_item_register("kernelSymbol.pmap_remove_options", xpf_find_pmap_remove_options, NULL);
  }
}