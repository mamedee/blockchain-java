package de.mamede.blockchain.model;

import sun.security.provider.DSAPublicKeyImpl;

import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;

public class Transaction implements Serializable {

   private byte[] from; //hash da conta (wallet) de origem
   private String fromFX; //dados de from em formato texto
   private byte[] to; //hash da conta (wallet) de destino
   private String toFX; //dados de to em formato texto
   private Integer value; //quantidade de moedas a ser enviadas
   private String timestamp; //timestamp do fechamento da transação
   private byte[] signature; //info encriptada de todos os campos 
   									//e será usada para verificar a valildade da transação.
   private  String signatureFX;
   private Integer ledgerId; //id do ledger (transação)

   //Constructor para carga de uma assinatura existente
   public Transaction(byte[] from, byte[] to, Integer value, byte[] signature, Integer ledgerId,
                      String timeStamp) {
   	
      Base64.Encoder encoder = Base64.getEncoder();
      
      this.from = from; //chave pública da conta (wallet) de origem
      this.fromFX = encoder.encodeToString(from); //chave pública da conta (wallet) de origem em texto
      this.to = to; //chave pública da conta (wallet) de destino
      this.toFX = encoder.encodeToString(to); //chave pública da conta (wallet) de destino em texto
      this.value = value;
      this.signature = signature;
      this.signatureFX = encoder.encodeToString(signature);
      this.ledgerId = ledgerId;
      this.timestamp = timeStamp;
   }
   
   //Constructor para criar uma nova transação e assiná-la.
   /*
    * fromWallet: contém a chave pública e privada criador da transação
    * signature: são os dados encriptados fornecidos pela chave privada do criador da transação.
    */
   public Transaction (Wallet fromWallet, byte[] toAddress, Integer value, Integer ledgerId,
                       Signature signing) throws InvalidKeyException, SignatureException {
      
   	Base64.Encoder encoder = Base64.getEncoder();
      
      this.from = fromWallet.getPublicKey().getEncoded();
      this.fromFX = encoder.encodeToString(fromWallet.getPublicKey().getEncoded());
      this.to = toAddress;
      this.toFX = encoder.encodeToString(toAddress);
      this.value = value;
      this.ledgerId = ledgerId;
      this.timestamp = LocalDateTime.now().toString();
      
      signing.initSign(fromWallet.getPrivateKey());
      String sr = this.toString();
      signing.update(sr.getBytes());
      
      this.signature = signing.sign(); //a assinatura é criada aqui
      this.signatureFX = encoder.encodeToString(this.signature);
   }

   public Boolean isVerified(Signature signing)
           throws InvalidKeyException, SignatureException {
      signing.initVerify(new DSAPublicKeyImpl(this.getFrom())); //prepara a chave pública de quem criou e assinou a transação
      signing.update(this.toString().getBytes()); //pega os dados da transação encriptados
      
      return signing.verify(this.signature); //verifica a chave pública + dados (fornecidos pelo verificador) com a assinatura (dados já encriptados e registrados na transação)
   }

   @Override
   public String toString() {
      return "Transaction{" +
              "from=" + Arrays.toString(from) +
              ", to=" + Arrays.toString(to) +
              ", value=" + value +
              ", timeStamp= " + timestamp +
              ", ledgerId=" + ledgerId +
              '}';
   }

   public byte[] getFrom() { return from; }
   public void setFrom(byte[] from) { this.from = from; }

   public byte[] getTo() { return to; }
   public void setTo(byte[] to) { this.to = to; }

   public Integer getValue() { return value; }
   public void setValue(Integer value) { this.value = value; }
   public byte[] getSignature() { return signature; }

   public Integer getLedgerId() { return ledgerId; }
   public void setLedgerId(Integer ledgerId) { this.ledgerId = ledgerId; }

   public String getTimestamp() { return timestamp; }

   public String getFromFX() { return fromFX; }
   public String getToFX() { return toFX; }
   public String getSignatureFX() { return signatureFX; }


   @Override
   public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof Transaction)) return false;
      Transaction that = (Transaction) o;
      return Arrays.equals(getSignature(), that.getSignature());
   }

   @Override
   public int hashCode() {
      return Arrays.hashCode(getSignature());
   }
}
