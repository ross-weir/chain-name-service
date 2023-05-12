{
  // Mint resolver action script
  //
  // TRANSACTIONS
  //
  // [1] Mint Resolver
  // Creates a resolver box/nft that is used for address resolution.
  // This action is called by users to create resolvers for their specified label (name) and registrar (TLD).
  //
  //   Input         |  Output        |  Data-Input
  // -----------------------------------------------
  // 0 Registry      |  Registry      |
  // 1 MintResolver  |  MintResolver  |
  // 2               |  Resolver      |
  //
  // REGISTERS
  //  R4: (Coll[Byte]) Label (name) that is used to resolve an address.
  //  R5: (Coll[Byte]) Registrar/TLD, "erg" for example.
  //  R6: (Coll[Byte]) Address to resolve to, this should be set based on the TLD.
  //                   For example if TLD is "erg" an Ergo address, if TLD is "ada" a Cardano address.
  //
  // VARIABLES
  //  0: (Coll[Byte]) Registrars AVL tree proof
  //  1: (Coll[Byte]) Resolvers AVL tree proof

  // constants
  // Could use a configuration box or something?
  val MaxLabelLength = 15 // could probably be longer?

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
  val label = SELF.R4[Coll[Byte]].get
  val tld = SELF.R5[Coll[Byte]].get
  val resolveAddress = SELF.R6[Coll[Byte]].get

  // scripts
  val resolverScriptHash = fromBase16("$resolverScriptHash")

  val expectedNftId = INPUTS(0).id

  // validity
  val validLabel = {
    val validLength = label.size <= MaxLabelLength
    // TODO label doesnt contain invalid characters

    validLength
  }

  val validTld = {
    val tldProof = getVar[Coll[Byte]](0).get
    val currentRegistrars = registryInBox.R4[AvlTree].get
    val hashedTld = blake2b256(tld)

    currentRegistrars.contains(hashedTld, tldProof)
  }

  val validResolverBox = {
    // valid script
    val validScript = blake2b256(resolverOutBox.propositionBytes) == resolverScriptHash
    // valid registers
    val validOutLabel = resolverOutBox.R4[Coll[Byte]].get == label
    val validOutTld = resolverOutBox.R5[Coll[Byte]].get == tld
    val validAddress = resolverOutBox.R6[Coll[Byte]].get == resolveAddress
    // valid nft
    val nft = resolverOutBox.tokens(0)
    val validOutNft = nft._1 == expectedNftId && nft._2 == 1L

    validScript && validOutLabel && validOutTld && validAddress && validOutNft
  }

  val validResolverTreeUpdate = {
    val resolversProof = getVar[Coll[Byte]](1).get
    val currentResolvers = registryInBox.R5[AvlTree].get
    val hashedResolver = blake2b256(label ++ tld)

    val insertOps: Coll[(Coll[Byte], Coll[Byte])] = Coll((hashedResolver, expectedNftId)) // expectedNftId validated in validResolverBox
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
    validLabel &&
    validTld &&
    validResolverBox &&
    validResolverTreeUpdate &&
    validFundsPaid &&
    validSuccessorBox
  )
}