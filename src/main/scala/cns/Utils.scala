package cns

import org.ergoplatform.ErgoAddressEncoder
import sigmastate.Values.ErgoTree
import sigmastate.eval.CompiletimeIRContext
import sigmastate.lang.{CompilerSettings, SigmaCompiler, TransformingSigmaBuilder}

object Utils {
  def compile(env: Map[String, Any], ergoScript: String, network: ErgoAddressEncoder.NetworkPrefix): ErgoTree = {
    val compiler = SigmaCompiler(CompilerSettings(network, TransformingSigmaBuilder, lowerMethodCalls = true))
    implicit val irContext: CompiletimeIRContext = new CompiletimeIRContext
    compiler.compile(env, ergoScript).buildTree.toSigmaProp
  }

  def bytesToHex(bytes: Array[Byte]): String = {
    bytes.map("%02x".format(_)).mkString
  }
}