package de.mamede.blockchain.model;

import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;

import sun.security.provider.DSAPublicKeyImpl;

public class Block implements Serializable {
	private byte[] previousHash; //dados encriptados (hash/assinatura) do bloco anterior
	private byte[] currentHash; //dados encriptados (hash/assinatura) do bloco atual
	private String timeStamp; //timestamp de mineração do bloco
	private byte[] minedBy; //chave pública que também é o endereço público do minerador (wallet) do bloco
	private Integer ledgerId = 1; //id do ledger (transação) para uso no banco de dados
	private Integer miningPoints = 0;
	private Double luck = 0.0;
	
	//Em um bloco, tem-se várias transações
	private ArrayList<Transaction> transactionLedger = new ArrayList<>();
	
	//este construtor é usado para retornar dados do banco de dados.
	public Block(byte[] previousHash, byte[] currentHash, String timeStamp,
				byte[] minedBy, Integer ledgerId, Integer miningPoints, Double luck) {
		this.previousHash = previousHash;
		this.currentHash = currentHash;
		this.timeStamp = timeStamp;
		this.minedBy = minedBy;
		this.ledgerId = ledgerId;
		this.miningPoints = miningPoints;
		this.luck = luck;
	}
	
	//construtor para iniciar o bloco após recuper=a-lo
	public Block(LinkedList<Block> currentBlockChain) {
		Block lastBlock = currentBlockChain.getLast();
		this.previousHash = lastBlock.getCurrentHash();
		this.ledgerId = lastBlock.getLedgerId() + 1;
		this.luck = Math.random() * 1000000;
	}
	
	//construtor apenas para criar o primeiro bloco da chain
	public Block() {
		this.previousHash = new byte[]{0};
	}
	
	/*
	 * A verificação do blockchain é feito com a chave pública/endereço a ser
	 * batida com o hash do bloco corrente/assinatura ao mesmo tempo em 
	 * que o hash dos dados deste bloco para ver se foi minerado por
	 * este minerador (minedBy).
	 */
	public Boolean isVerified(Signature signing)
			throws InvalidKeyException, SignatureException {
		
		signing.initVerify(new DSAPublicKeyImpl(this.minedBy));
		signing.update(this.toString().getBytes());
		
		return signing.verify(this.currentHash);
	}
	
	@Override
   public String toString() {
       return "Block{" +
               "previousHash=" + Arrays.toString(this.previousHash) +
               ", timeStamp='" + timeStamp + '\'' +
               ", minedBy=" + Arrays.toString(minedBy) +
               ", ledgerId=" + ledgerId +
               ", miningPoints=" + miningPoints +
               ", luck=" + luck +
               '}';
   }
	
	@Override
   public int hashCode() {
       return Arrays.hashCode(getPreviousHash());
   }
	
	@Override
   public boolean equals(Object o) {
		
       if (this == o) 
      	 return true;
      
       if (!(o instanceof Block)) 
      	 return false;
       
       Block block = (Block) o;
       
       return Arrays.equals(getPreviousHash(), block.getPreviousHash());
   }
	
	// Getters and setters ---------------------------------------
	
	public byte[] getPreviousHash() {
		return previousHash;
	}

	public void setPreviousHash(byte[] previousHash) {
		this.previousHash = previousHash;
	}

	public byte[] getCurrentHash() {
		return currentHash;
	}

	public void setCurrentHash(byte[] currentHash) {
		this.currentHash = currentHash;
	}

	public String getTimeStamp() {
		return timeStamp;
	}

	public void setTimeStamp(String timeStamp) {
		this.timeStamp = timeStamp;
	}

	public byte[] getMinedBy() {
		return minedBy;
	}

	public void setMinedBy(byte[] minedBy) {
		this.minedBy = minedBy;
	}

	public Integer getLedgerId() {
		return ledgerId;
	}

	public void setLedgerId(Integer ledgerId) {
		this.ledgerId = ledgerId;
	}

	public Integer getMiningPoints() {
		return miningPoints;
	}

	public void setMiningPoints(Integer miningPoints) {
		this.miningPoints = miningPoints;
	}

	public Double getLuck() {
		return luck;
	}

	public void setLuck(Double luck) {
		this.luck = luck;
	}

	public ArrayList<Transaction> getTransactionLedger() {
		return transactionLedger;
	}

	public void setTransactionLedger(ArrayList<Transaction> transactionLedger) {
		this.transactionLedger = transactionLedger;
	}
}
