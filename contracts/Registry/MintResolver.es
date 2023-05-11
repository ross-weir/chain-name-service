{
  // Mint resolver action script
  //
  // TRANSACTIONS
  //
  // [1] Mint Resolver
  // Creates a resolver box/nft that is used for address resolution.
  // This action is called by users to create resolvers for their specified name and registrar.
  //
  //   Input         |  Output        |  Data-Input
  // -----------------------------------------------
  // 0 Registry      |  Registry      |
  // 1 MintResolver  |  MintResolver  |
  // 2               |  Resolver      |
  //
  // REGISTERS
  //  R4: (Coll[Byte]) Name that is used to resolve an address.
  //  R5: (Coll[Byte]) Registrar/TLD, "erg" for example.
  //  R6: (Coll[Byte]) Address to resolve to, this should be set based on the TLD.
  //                   For example if TLD is "erg" an Ergo address, if TLD is "ada" a Cardano address.
  // VARIABLES
  //  0: (Coll[Byte]) Registrars AVL tree proof
  //  1: (Coll[Byte]) Resolvers AVL tree proof

  // indexes
  val registryIndex = 0
  val selfIndex = 1
  val resolverIndex = 2

  // boxes
  val successorOutBox = OUTPUTS(selfIndex)
  val registryInBox = INPUTS(registryIndex)
  val registryOutBox = OUTPUTS(registryIndex)
  val resolverOutBox = OUTPUTS(resolverIndex)

  // registers
  val name = SELF.R4[Coll[Byte]].get
  val registrarTld = SELF.R5[Coll[Byte]].get

  // scripts
  val resolverScriptHash = fromBase16("$resolverScriptHash")

  // validity
  val validName = {
    // name doesnt contain invalid characters
    // name is below max length
    true
  }

  val validTld = {
    val tldProof = getVar[Coll[Byte]](0).get
    val currentRegistrars = registryInBox.R4[AvlTree].get
    val hashedTld = blake2b256(registrarTld)

    currentRegistrars.contains(hashedTld, tldProof)
  }

  val validResolverBox = {
    val validScript = blake2b256(resolverOutBox.propositionBytes) == resolverScriptHash
    // out box r4 should be the name
    // out box r5 should be the tld
    // out box should have token with 1 count (NFT), tokens(0)._2 == 1L
    //    origin of the nft is used to prove authenticity
    //    namehash -> nft key,values should be added to registrys resolver AVL tree
    true
  }

  val validResolverTreeUpdate = {
    val resolversProof = getVar[Coll[Byte]](1).get
    val currentResolvers = registryInBox.R5[AvlTree].get

    // TODO do we need to check if name already exists?
    // TODO concat properly
    val hashedResolver = blake2b256(name ++ tld)
    // TODO get actual nft value
    val resolverNft = fromBase16("01")

    val insertOps: Coll[(Coll[Byte], Coll[Byte])] = Coll((hashedResolver, resolverNft))
    val expectedResolvers = currentResolvers.insert(insertOps, resolversProof).get
    val updatedResolvers = registryOutBox.R5[AvlTree].get

    expectedResolvers.digest == updatedResolvers.digest
  }

  val validFundsPaid = {
    val amountPaid = registryOutBox.value - registryInBox.value

    // TODO actual price calculations
    amountPaid > 100000
  }

  // successor box valid
  val validSuccessorBox = successorOutBox.propositionBytes == SELF.propositionBytes && // script preserved
    successorOutBox.tokens == SELF.tokens // nft preserved

  sigmaProp(
    validName &&
    validTld &&
    validResolverBox &&
    validResolverTreeUpdate &&
    validFundsPaid &&
    validSuccessorBox
  )
}