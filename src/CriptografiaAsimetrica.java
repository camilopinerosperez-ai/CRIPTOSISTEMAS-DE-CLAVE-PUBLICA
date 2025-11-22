import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

/**
 * Demostración de Criptografía Asimétrica usando RSA
 * Este programa ilustra los conceptos básicos de criptosistemas de clave pública
 *
 * @author Camilo - UNIMINUTO
 * @version 1.0
 */
public class CriptografiaAsimetrica {

    private KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    /**
     * Constructor que genera el par de claves RSA
     */
    public CriptografiaAsimetrica() throws NoSuchAlgorithmException {
        // Generar par de claves RSA de 2048 bits
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        this.keyPair = keyGen.generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();

        System.out.println("=== Par de Claves RSA Generado ===");
        System.out.println("Tamaño de clave: 2048 bits\n");
    }

    /**
     * Cifra un mensaje usando la clave pública
     * @param mensaje Texto plano a cifrar
     * @return Texto cifrado en Base64
     */
    public String cifrarConClavePublica(String mensaje) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] mensajeCifrado = cipher.doFinal(mensaje.getBytes("UTF-8"));
        String mensajeCifradoBase64 = Base64.getEncoder().encodeToString(mensajeCifrado);

        System.out.println("--- CIFRADO CON CLAVE PÚBLICA ---");
        System.out.println("Mensaje original: " + mensaje);
        System.out.println("Mensaje cifrado: " + mensajeCifradoBase64.substring(0, 50) + "...");
        System.out.println();

        return mensajeCifradoBase64;
    }

    /**
     * Descifra un mensaje usando la clave privada
     * @param mensajeCifrado Texto cifrado en Base64
     * @return Texto plano descifrado
     */
    public String descifrarConClavePrivada(String mensajeCifrado) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] mensajeBytes = Base64.getDecoder().decode(mensajeCifrado);
        byte[] mensajeDescifrado = cipher.doFinal(mensajeBytes);
        String resultado = new String(mensajeDescifrado, "UTF-8");

        System.out.println("--- DESCIFRADO CON CLAVE PRIVADA ---");
        System.out.println("Mensaje descifrado: " + resultado);
        System.out.println();

        return resultado;
    }

    /**
     * Firma digitalmente un mensaje usando la clave privada
     * @param mensaje Mensaje a firmar
     * @return Firma digital en Base64
     */
    public String firmarMensaje(String mensaje) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(mensaje.getBytes("UTF-8"));

        byte[] firmaBytes = signature.sign();
        String firmaBase64 = Base64.getEncoder().encodeToString(firmaBytes);

        System.out.println("--- FIRMA DIGITAL ---");
        System.out.println("Mensaje firmado: " + mensaje);
        System.out.println("Firma generada: " + firmaBase64.substring(0, 50) + "...");
        System.out.println();

        return firmaBase64;
    }

    /**
     * Verifica la firma digital usando la clave pública
     * @param mensaje Mensaje original
     * @param firmaBase64 Firma digital en Base64
     * @return true si la firma es válida
     */
    public boolean verificarFirma(String mensaje, String firmaBase64) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(mensaje.getBytes("UTF-8"));

        byte[] firmaBytes = Base64.getDecoder().decode(firmaBase64);
        boolean esValida = signature.verify(firmaBytes);

        System.out.println("--- VERIFICACIÓN DE FIRMA ---");
        System.out.println("Mensaje verificado: " + mensaje);
        System.out.println("¿Firma válida?: " + (esValida ? "SÍ ✓" : "NO ✗"));
        System.out.println();

        return esValida;
    }

    /**
     * Muestra información de las claves generadas
     */
    public void mostrarInformacionClaves() {
        System.out.println("=== INFORMACIÓN DE CLAVES ===");
        System.out.println("Clave Pública (primeros 100 caracteres):");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()).substring(0, 100) + "...");
        System.out.println("\nClave Privada (primeros 100 caracteres):");
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()).substring(0, 100) + "...");
        System.out.println("\nAlgoritmo: " + publicKey.getAlgorithm());
        System.out.println("Formato: " + publicKey.getFormat());
        System.out.println("\n");
    }

    /**
     * Método principal que demuestra todos los conceptos
     */
    public static void main(String[] args) {
        try {
            System.out.println("╔═══════════════════════════════════════════════════════════╗");
            System.out.println("║   DEMOSTRACIÓN DE CRIPTOGRAFÍA ASIMÉTRICA - RSA          ║");
            System.out.println("║   Caso Práctico: Sistema de Mensajería Segura            ║");
            System.out.println("╚═══════════════════════════════════════════════════════════╝\n");

            // Crear instancia y generar claves
            CriptografiaAsimetrica crypto = new CriptografiaAsimetrica();

            // Mostrar información de las claves
            crypto.mostrarInformacionClaves();

            // ESCENARIO 1: Confidencialidad (Cifrado/Descifrado)
            System.out.println("╔═══════════════════════════════════════════════════════════╗");
            System.out.println("║   ESCENARIO 1: CONFIDENCIALIDAD                           ║");
            System.out.println("║   Usuario A envía mensaje confidencial a Usuario B        ║");
            System.out.println("╚═══════════════════════════════════════════════════════════╝\n");

            String mensajeSecreto = "Información confidencial: El servidor estará en mantenimiento el 25/11/2025";
            String mensajeCifrado = crypto.cifrarConClavePublica(mensajeSecreto);
            String mensajeDescifrado = crypto.descifrarConClavePrivada(mensajeCifrado);

            System.out.println("✓ El mensaje ha sido protegido exitosamente\n");
            System.out.println("═══════════════════════════════════════════════════════════\n");

            // ESCENARIO 2: Autenticidad e Integridad (Firma Digital)
            System.out.println("╔═══════════════════════════════════════════════════════════╗");
            System.out.println("║   ESCENARIO 2: AUTENTICIDAD E INTEGRIDAD                  ║");
            System.out.println("║   Usuario B firma un documento importante                 ║");
            System.out.println("╚═══════════════════════════════════════════════════════════╝\n");

            String documento = "Contrato de prestación de servicios - Valor: $50.000.000";
            String firma = crypto.firmarMensaje(documento);
            boolean firmaValida = crypto.verificarFirma(documento, firma);

            if (firmaValida) {
                System.out.println("✓ El documento es auténtico y no ha sido modificado\n");
            }

            // Intentar verificar con documento alterado
            System.out.println("--- Prueba de Seguridad: Documento Alterado ---");
            String documentoAlterado = "Contrato de prestación de servicios - Valor: $100.000.000";
            boolean firmaInvalida = crypto.verificarFirma(documentoAlterado, firma);

            if (!firmaInvalida) {
                System.out.println("✓ Sistema detectó correctamente la alteración del documento\n");
            }

            System.out.println("═══════════════════════════════════════════════════════════\n");

            // RESUMEN DE APLICACIONES PRÁCTICAS
            System.out.println("╔═══════════════════════════════════════════════════════════╗");
            System.out.println("║   APLICACIONES PRÁCTICAS EN TELEFÓNICA                    ║");
            System.out.println("╚═══════════════════════════════════════════════════════════╝");
            System.out.println("✓ Autenticación de usuarios en sistemas corporativos");
            System.out.println("✓ Cifrado de comunicaciones entre servicios");
            System.out.println("✓ Firma digital de contratos y documentos legales");
            System.out.println("✓ Intercambio seguro de claves simétricas (SSL/TLS)");
            System.out.println("✓ Protección de APIs y microservicios");
            System.out.println("✓ Validación de integridad en actualizaciones de software\n");

            System.out.println("╔═══════════════════════════════════════════════════════════╗");
            System.out.println("║   DEMOSTRACIÓN COMPLETADA EXITOSAMENTE                    ║");
            System.out.println("╚═══════════════════════════════════════════════════════════╝");

        } catch (Exception e) {
            System.err.println("Error en la demostración: " + e.getMessage());
            e.printStackTrace();
        }
    }
}