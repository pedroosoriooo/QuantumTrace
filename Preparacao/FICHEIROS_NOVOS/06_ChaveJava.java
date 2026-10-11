import javax.crypto.KeyGenerator;

// Exemplo sintetico para inspecao; nao compilar nem executar na demonstracao.
class ChaveJava {
    public static void main(String[] args) throws Exception {
        KeyGenerator gerador = KeyGenerator.getInstance("AES");
        gerador.init(256);
        gerador.generateKey();
    }
}
