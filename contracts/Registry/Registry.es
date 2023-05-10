{
  // Registry script
  //
  // TRANSACTIONS
  //
  // [1] New Registrar
  // Creates a new TLD registrar for this registry thus allowing minting of resolvers for that TLD.
  // An example of a TLD could be "erg" to allow for "myname.erg" names or similarly "ada" for "myname.ada"
  // which would allow minting resolvers for Cardano addresses.
  //
  // This is a privlidged operation performed by registry admins.
  // TLDs have functional use - not cosmetic, so we don't want to allow arbitrary registrars.
  // It only really makes sense to have registrars for Ergo + chains that have working bridges.
  //
  //   Input         |  Output        |  Data-Input
  // -----------------------------------------------
  // 0 Registry      |  Registry      |  RegistryAdmin
  // 1 NewRegistrar  |  NewRegistrar  |
  //
  // REGISTERS
  //  R4: (AvlTree) Registrars Avl tree
  //  R5: (AvlTree) Resolvers Avl tree

  // indexes
  val selfIndex = 0
  val actionIndex = 1

  // boxes
  val successorOutBox = OUTPUTS(selfIndex)
  val actionInBox = INPUTS(actionIndex)

  // nfts
  val newRegistrarNft = fromBase64("$newRegistrarNft")
  val mintResolverNft = fromBase64("$mintResolverNft")

  // registers
  val inRegistrarsState = SELF.R4[AvlTree].get
  val outRegistrarsState = successorOutBox.R4[AvlTree].get
  val inResolversState = SELF.R5[AvlTree].get
  val outResolversState = successorOutBox.R5[AvlTree].get

  // validity checks
  val validNewRegistrar = actionInBox.tokens(0)._1 == newRegistrarNft
  val validMintResolver = actionInBox.tokens(0)._1 == mintResolverNft

  // check registrars & resolver trees
  val validRegistrars = if (!validNewRegistrar) {
    inRegistrarsState.digest == outRegistrarsState.digest // ensure registrars are unchanged
  } else true // NewRegistrar script will validate/update tree

  val validResolvers = if (!validMintResolver) {
    inResolversState.digest == outResolversState.digest // ensure resolvers are unchanged
  } else true // MintResolver script will validate/update tree

  val validSuccessorBox = successorOutBox.propositionBytes == SELF.propositionBytes &&
    validRegistrars &&
    validResolvers

  val validAction = validNewRegistrar || validMintResolver

  sigmaProp(validSuccessorBox && validAction)
}