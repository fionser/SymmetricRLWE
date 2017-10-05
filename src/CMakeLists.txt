set(
    SymRLWE_SRC 
    Cipher.cpp
    types.cpp
    PrivateKey.cpp
    GreaterThan.cpp
    PrivateGreaterThan.cpp
    )
add_library(symrlwe STATIC ${SymRLWE_SRC})
