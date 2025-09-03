# Assets Folder

Esta pasta contém os recursos estáticos do auth-service.

## Logo do Email

Coloque o arquivo `logo.png` nesta pasta para que ele apareça automaticamente nos emails de cadastro.

**Estrutura esperada:**
```
src/
  assets/
    logo.png    ← Sua logo aqui
```

**Especificações da logo:**
- Formato: PNG
- Largura máxima: 200px (será redimensionada automaticamente)
- Tamanho do arquivo: < 50KB (recomendado)
- Resolução: 72-150 DPI

A logo será convertida automaticamente para Base64 e incorporada nos emails.
