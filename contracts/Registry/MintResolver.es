{
  // Mint resolver action script
  //
  // TRANSACTIONS
  //
  // [1] Mint Resolver
  // Creates a resolver box/nft that is used for address resolution.
  // This action is called by users to create resolvers for their specified label (name) and registrar (TLD).
  //
  // The buyer must submit a commitment box in the transaction to prevent frontrunning.
  // A commitment is valid if:
  //  - The box was created more than `MinCommitmentAge` blocks ago & less than `MaxCommitmentAge` blocks ago.
  //  - The R4 of the box contains a value of blake2b256(secret ++ encoded(buyerPk) ++ label ++ tld ++ address) - commitment hash.
  //
  //   Input         |  Output        |  Data-Input
  // -----------------------------------------------
  // 0 Registry      |  Registry      |
  // 1 MintResolver  |  MintResolver  |
  // 2 Commitment    |  Resolver      |
  //
  // REGISTERS
  //  R4: (Coll[Byte])    Commitment secret.
  //  R5: (GroupElement)  PK of the buyer, transaction must be signed with the associated SK to ensure
  //                        the buyer can spend/use the Resolver.
  //  R6: (Coll[Byte])    Label (name) that is used to resolve an address.
  //  R7: (Coll[Byte])    Registrar/TLD, "erg" for example.
  //  R8: (Coll[Byte])    Address to resolve to, this should be set based on the TLD.
  //                        For example if TLD is "erg" an Ergo address, if TLD is "ada" a Cardano address.
  //
  // VARIABLES
  //  0: (Coll[Byte]) Registrars AVL tree proof
  //  1: (Coll[Byte]) Resolvers AVL tree proof

  // constants
  // Could use a configuration box or something?
  val MinLabelLength = 3
  val MaxLabelLength = 15 // could probably be longer
  val MinCommitmentAge = 3 // 3 blocks, ~30 mins
  val MaxCommitmentAge = 18 // 18 blocks, ~3 hours

  // indexes
  val registryIndex = 0
  val selfIndex = 1
  val resolverOutIndex = 2
  val commitmentInIndex = 2

  // boxes
  val successorOutBox = OUTPUTS(selfIndex)
  val registryInBox = INPUTS(registryIndex)
  val registryOutBox = OUTPUTS(registryIndex)
  val resolverOutBox = OUTPUTS(resolverOutIndex)
  val commitmentInBox = INPUTS(commitmentInIndex)

  // registers
  val commitmentSecret = SELF.R4[Coll[Byte]].get
  val buyerPk = SELF.R5[GroupElement].get
  val label = SELF.R6[Coll[Byte]].get
  val tld = SELF.R7[Coll[Byte]].get
  val resolveAddress = SELF.R8[Coll[Byte]].get

  // scripts
  val resolverScriptHash = fromBase16("$resolverScriptHash")

  val expectedNftId = INPUTS(0).id

  // validity
  val validCommitment = {
    // valid commit age
    val commitAge = HEIGHT - commitmentInBox.creationInfo._1
    val validCommitAge = commitAge >= MinCommitmentAge && commitAge <= MaxCommitmentAge
    // valid commit hash
    val expectedCommitment = blake2b256(
      commitmentSecret ++
      buyerPk.getEncoded ++
      label ++
      tld ++
      resolveAddress
    )
    val actualCommitment = commitmentInBox.R4[Coll[Byte]].get

    (expectedCommitment == actualCommitment) && validCommitAge
  }

  // ensure buyer can actually use the Resolver
  val validOwner = proveDlog(buyerPk)

  val validLabel = {
    val validLength = label.size <= MaxLabelLength && label.size >= MinLabelLength
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
    val validOwnerPk = resolverOutBox.R4[GroupElement].get == buyerPk
    val validOutLabel = resolverOutBox.R5[Coll[Byte]].get == label
    val validOutTld = resolverOutBox.R6[Coll[Byte]].get == tld
    val validAddress = resolverOutBox.R7[Coll[Byte]].get == resolveAddress
    // valid nft
    val nft = resolverOutBox.tokens(0)
    val validOutNft = nft._1 == expectedNftId && nft._2 == 1L

    validScript && validOwnerPk && validOutLabel && validOutTld && validAddress && validOutNft
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

    // TODO payment to contract dev
    // TODO payment to ui dev
    // TODO remaining funds to DAO
    // TODO actual price calculations
    amountPaid > 100000
  }

  // successor box valid
  val validSuccessorBox = successorOutBox.propositionBytes == SELF.propositionBytes && // script preserved
    successorOutBox.tokens == SELF.tokens // nft preserved

  validOwner && sigmaProp(
    validCommitment &&
    validLabel &&
    validTld &&
    validResolverBox &&
    validResolverTreeUpdate &&
    validFundsPaid &&
    validSuccessorBox
  )
}