find_path   (GMP_INCLUDE_DIRS    NAMES gmp.h     )
find_library(GMP_LIBRARIES       NAMES gmp libgmp)
				 
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GMP DEFAULT_MSG GMP_INCLUDE_DIR GMP_LIBRARIES)
