package com.generation.lojadegames.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.generation.lojadegames.model.Produto;

public interface ProdutoRepository extends JpaRepository<Produto, Long>{

	public List<Produto> findAllByNomeContainingIgnoreCase(String nome);

	public List<Produto> findAllByPrecoLessThan(float preco);

	public List<Produto> findAllByPrecoGreaterThan(float preco); 

}
