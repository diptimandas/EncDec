package com.example.EncDec;




//package com.example.Jakar.Controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;

@RestController
@RequestMapping("/file")
public class Controller {

    private static final String ALGORITHM = "AES";
    private static final String SALT = "mySalt123";
    private static final byte[] MARKER_BYTES = "ENC:".getBytes(StandardCharsets.UTF_8);

    @PostMapping("/encrypt")
    public ResponseEntity<?> encryptFile(@RequestParam("file") MultipartFile file,
                                         @RequestParam("password") String password) {
        try {
            byte[] fileBytes = file.getBytes();

            // Check if file already starts with the marker by comparing bytes directly
            if (fileBytes.length >= MARKER_BYTES.length) {
                boolean alreadyEncrypted = true;
                for (int i = 0; i < MARKER_BYTES.length; i++) {
                    if (fileBytes[i] != MARKER_BYTES[i]) {
                        alreadyEncrypted = false;
                        break;
                    }
                }
                if (alreadyEncrypted) {
                    return ResponseEntity.badRequest()
                            .body("File is already encrypted! Cannot encrypt again.");
                }
            }

            // Encrypt the file bytes
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, getKeyFromPassword(password));
            byte[] encryptedBytes = cipher.doFinal(fileBytes);

            // Prepend the marker to the encrypted bytes
            byte[] result = new byte[MARKER_BYTES.length + encryptedBytes.length];
            System.arraycopy(MARKER_BYTES, 0, result, 0, MARKER_BYTES.length);
            System.arraycopy(encryptedBytes, 0, result, MARKER_BYTES.length, encryptedBytes.length);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=encrypted_" + file.getOriginalFilename())
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Encryption failed! Please try again.");
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<?> decryptFile(@RequestParam("file") MultipartFile file,
                                         @RequestParam("password") String password) {
        try {
            byte[] fileBytes = file.getBytes();

            // Check if the file starts with the marker; if not, return error
            if (fileBytes.length < MARKER_BYTES.length) {
                return ResponseEntity.badRequest().body("File is not encrypted or missing marker!");
            }
            boolean markerFound = true;
            for (int i = 0; i < MARKER_BYTES.length; i++) {
                if (fileBytes[i] != MARKER_BYTES[i]) {
                    markerFound = false;
                    break;
                }
            }
            if (!markerFound) {
                return ResponseEntity.badRequest().body("File is not encrypted or missing marker!");
            }

            // Remove marker bytes from the fileBytes
            int dataLength = fileBytes.length - MARKER_BYTES.length;
            byte[] dataToDecrypt = new byte[dataLength];
            System.arraycopy(fileBytes, MARKER_BYTES.length, dataToDecrypt, 0, dataLength);

            // Decrypt the file bytes
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, getKeyFromPassword(password));
            byte[] decryptedBytes = cipher.doFinal(dataToDecrypt);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=decrypted_" + file.getOriginalFilename())
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(decryptedBytes);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body("Decryption failed! Maybe the file is not encrypted or the password is incorrect.");
        }
    }

    private SecretKeySpec getKeyFromPassword(String password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), SALT.getBytes(StandardCharsets.UTF_8), 65536, 256);
        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
        return new SecretKeySpec(secretKey.getEncoded(), ALGORITHM);
    }
}
