set(
    SymRLWE_SRC 
    Cipher.cpp
    types.cpp
    net_io.cpp
    PrivateKey.cpp
    GreaterThan.cpp
    PrivateGreaterThan.cpp
    PPDTServer.cpp
    PPDTClient.cpp
    Timer.cpp
    )
add_library(symrlwe STATIC ${SymRLWE_SRC})
