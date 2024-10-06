Este projeto é uma ferramenta de monitoramento de executáveis Portable Executable (PE) que permite ao usuário escolher um arquivo executável para ser iniciado. 
Ao escolher o executável, o projeto intercepta e monitora chamadas de função do Windows, utilizando técnicas de **hooking de API Windows** para registrar e analisar o comportamento do aplicativo em execução. 
No momento, somente funciona com CreateFileW.
