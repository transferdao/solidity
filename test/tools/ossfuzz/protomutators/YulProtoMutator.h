#pragma once

#include <test/tools/ossfuzz/yulProto.pb.h>

#include <libsolutil/Common.h>

#include <src/libfuzzer/libfuzzer_macro.h>

#include <random>

namespace solidity::yul::test::yul_fuzzer
{

using ProtobufMessage = google::protobuf::Message;
using ProtobufDesc = google::protobuf::Descriptor;

template <typename Proto>
using LPMPostProcessor = protobuf_mutator::libfuzzer::PostProcessorRegistration<Proto>;

template <typename Proto>
using FuzzMutatorCallback = std::function<void(Proto*, unsigned int)>;

template <typename P>
struct YulProtoCBRegistration
{
	YulProtoCBRegistration(FuzzMutatorCallback<P> const& _callback)
	{
		LPMPostProcessor<P> reg = {_callback};
	}
};

class MutationInfo: public ScopeGuard
{
public:
	MutationInfo(ProtobufMessage* _message, std::string const& _info);

	static void print(std::string const& _str)
	{
		std::cout << _str << std::endl;
	}
	void exitInfo();

	ProtobufMessage* m_protobufMsg;
};

struct YulRandomNumGenerator
{
	using RandomEngine = std::minstd_rand;

	explicit YulRandomNumGenerator(unsigned _seed): m_random(RandomEngine(_seed)) {}

	unsigned operator()()
	{
		return m_random();
	}

	RandomEngine m_random;
};

template <typename Proto>
using CustomFuzzMutator = std::function<void(Proto*, YulRandomNumGenerator& _rand)>;

struct YulProtoMutator
{
	enum class PrintChanges { Yes, No };

	template <typename T>
	static void functionWrapper(
		CustomFuzzMutator<T> const& _callback,
		T* _message,
		unsigned int _seed,
		unsigned _period,
		std::string const& _info,
		PrintChanges _printChanges = PrintChanges::No
	);

	/// Return an integer literal of the given value.
	/// @param _value: Value of the integer literal
	static Literal* intLiteral(unsigned _value);

	/// Return a variable reference
	/// @param _seed: Pseudo-random unsigned integer used as index
	/// of variable to be referenced
	static VarRef* varRef(unsigned _seed);

	/// Return a literal expression
	/// @param _value: value of literal expression
	static Expression* litExpression(unsigned _value);

	/// Return a reference expression
	/// @param _seed: Pseudo-random unsigned integer used as index
	/// of variable to be referenced
	static Expression* refExpression(YulRandomNumGenerator& _rand);

	/// Return a load expression from location zero
	/// @param _seed: Pseudo-random unsigned integer used to create
	/// type of load i.e., memory, storage, or calldata.
	static Expression* loadExpression(YulRandomNumGenerator& _rand);

	static Expression* loadFromZero(YulRandomNumGenerator& _rand);

	/// Configure function call from a pseudo-random seed.
	/// @param _call: Pre-allocated FunctionCall protobuf message
	/// @param _seed: Pseudo-random unsigned integer
	static void configureCall(FunctionCall *_call, YulRandomNumGenerator& _rand);

	/// Configure function call arguments.
	/// @param _callType: Enum stating type of function call
	/// i.e., no-return, single-return, multi-decl, or multi-assign.
	/// @param _call: Pre-allocated protobuf message of FunctionCall type
	/// @param _seed: Pseudo-random unsigned integer.
	static void configureCallArgs(
		FunctionCall_Returns _callType,
		FunctionCall *_call,
		YulRandomNumGenerator& _rand
	);

	/// Clear protobuf expression
	/// @param _expr: Protobuf expression to be cleared
	static void clearExpr(Expression* _expr);

	/// Convert all expression-type arguments of statement
	/// to a given type.
	static void addArgs(
		Statement* _stmt,
		std::function<Expression*(YulRandomNumGenerator&)>,
		YulRandomNumGenerator& _rand
	);

	/// Apply mutator to unset expression-type statement
	/// arguments.
	/// @param _stmt: Statement to be mutated
	/// @param _seed: Pseudo-random unsigned integer
	/// @param _mutator: Mutator function that accepts an unset expression-type
	/// statement argument and a pseudo-random integer and applies
	/// the mutation function to it
	static void addArgsRec(
		Statement* _stmt,
		std::function<void(Expression*, YulRandomNumGenerator& _rand)> _mutator,
		YulRandomNumGenerator& _rand
	);

	/// Add a new statement to block
	static void addStmt(Block *_block, YulRandomNumGenerator& _rand);

	/// Create binary op expression of two variable references.
	static Expression* binopExpression(YulRandomNumGenerator& _rand);

	static void unsetExprMutator(
		Expression* _expr,
		YulRandomNumGenerator& _rand,
		std::function<void(Expression*, unsigned)> _mutateExprFunc
	);

	/// Check if expression is set.
	static bool set(Expression const& _expr)
	{
		return _expr.expr_oneof_case() != Expression::EXPR_ONEOF_NOT_SET;
	}

	/// Helper type for type matching visitor.
	template<class T> struct AlwaysFalse: std::false_type {};

	/// Template struct for obtaining a valid enum value of
	/// template type from a pseudo-random unsigned integer.
	/// @param _seed: Pseudo-random integer
	/// @returns Valid enum of enum type T
	template <typename T>
	struct EnumTypeConverter
	{
		T enumFromSeed(unsigned _seed)
		{
			return validEnum(_seed);
		}

		/// Return a valid enum of type T from _seed
		T validEnum(unsigned _seed);
		/// Return maximum enum value for enum of type T
		static int enumMax();
		/// Return minimum enum value for enum of type T
		static int enumMin();
	};

	/// Modulo for mutations that should occur rarely
	static constexpr unsigned s_lowIP = 11;
	/// Modulo for mutations that should occur not too often
	static constexpr unsigned s_mediumIP = 7;
	/// Modulo for mutations that should occur often
	static constexpr unsigned s_highIP = 5;
};
}
