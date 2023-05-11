{
  // New Registrar action script
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
  // This box: new-registrar box
  //
  // TOKENS
  //  tokens(0): newRegistrarNft
  //
  // REGISTERS
  //  R4: (Coll[Byte]) TLD name (Normally a chains main currency ticker as lowercase: "erg" / "ada")
  //
  // VARIABLES
  //  0: (Coll[Byte]) Registrar AVL tree proof

  // indexes
  val registryIndex = 0
  val selfIndex = 1

  // data inputs
  val registryAdminBoxIndex = 0

  // nfts
  val registryAdminNft = fromBase16("$registryAdminNft")

  // boxes
  val successorOutBox = OUTPUTS(selfIndex)
  val registryInBox = INPUTS(registryIndex)
  val registryOutBox = OUTPUTS(registryIndex)
  val registryAdminBox = CONTEXT.dataInputs(registryAdminBoxIndex)

  // validity
  val validNewRegistrar = {
    val proof = getVar[Coll[Byte]](0).get
    val newRegistrar = blake2b256(SELF.R4[Coll[Byte]].get)
    val currentRegistrars = registryInBox.R4[AvlTree].get

    // registrar shouldn't already exist
    val registrarExists = currentRegistrars.contains(newRegistrar, proof)

    // registrars state updated correctly
    val insertVal: Coll[Byte] = Coll(1.toByte)
    val insertOps: Coll[(Coll[Byte], Coll[Byte])] = Coll((newRegistrar, insertVal))

    val expectedRegistrarsState = currentRegistrars.insert(insertOps, proof).get
    val actualRegistrarsState = registryOutBox.R4[AvlTree].get
    val validStateUpdate = expectedRegistrarsState.digest == actualRegistrarsState.digest

    !registrarExists && validStateUpdate
  }

  // successor box valid
  val validSuccessorBox = successorOutBox.propositionBytes == SELF.propositionBytes && // script preserved
    successorOutBox.tokens == SELF.tokens // nft preserved

  // user permissions valid
  // TODO can anyone use this as a data input or only the owner of the box?
  // this might need to be a spendable box, not a data input
  val isAdmin = registryAdminBox.tokens(0)._1 == registryAdminNft

  sigmaProp(isAdmin && validSuccessorBox && validNewRegistrar)
}