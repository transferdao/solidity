#include <libsolidity/analysis/FunctionCallGraph.h>
//#include <libsolutil/CommonData.h>

#include <boost/range/adaptor/reversed.hpp>

using namespace solidity::frontend;

void FunctionCallGraphBuilder::analyze()
{
	for (auto const* contract: m_currentContract->annotation().linearizedBaseContracts  | boost::adaptors::reversed)
		if (contract->constructor())
			contract->constructor()->accept(*this);

	for (VariableDeclaration const* stateVar: m_currentContract->stateVariablesIncludingInherited())
		if (stateVar->value())
		{
			m_currentNode = stateVar;
			stateVar->value()->accept(*this);
			m_mapping.insert(std::pair(stateVar, std::move(m_currentMapping)));
		}
}


bool FunctionCallGraphBuilder::visit(FunctionDefinition const& _functionDefinition)
{
	return analyseCallable(_functionDefinition);
}


bool FunctionCallGraphBuilder::visit(ModifierDefinition const& _modifierDefinition)
{
	return analyseCallable(_modifierDefinition);
}


bool FunctionCallGraphBuilder::visit(Identifier const& _identifier)
{
	if (auto const callableDef = dynamic_cast<CallableDeclaration const*>(_identifier.annotation().referencedDeclaration))
		if (m_currentMapping.insert(callableDef).second)
			findFinalOverride(callableDef)->accept(*this);

	return false;
}


bool FunctionCallGraphBuilder::analyseCallable(CallableDeclaration const& _callableDeclaration)
{
	Declaration const* previousNode = std::move(m_currentNode);
	std::set<CallableDeclaration const*, CompareDef> previousMapping = std::move(m_currentMapping);

	m_currentNode = &_callableDeclaration;
	m_currentMapping.clear();

	if (FunctionDefinition const* funcDef = dynamic_cast<decltype(funcDef)>(&_callableDeclaration))
	{
		ASTNode::listAccept(funcDef->modifiers(), *this);
		funcDef->body().accept(*this);
	}
	else if (ModifierDefinition const* modDef = dynamic_cast<decltype(modDef)>(&_callableDeclaration))
	{
		modDef->body().accept(*this);
	}

	m_mapping.emplace(m_currentNode, m_currentMapping);

	if (previousNode != nullptr)
		previousMapping.merge(m_currentMapping);
	m_currentMapping = std::move(previousMapping);

	m_currentNode = previousNode;

	return false;
}

CallableDeclaration const* FunctionCallGraphBuilder::findFinalOverride(CallableDeclaration const* _callable)
{
	if (!_callable->virtualSemantics())
		return _callable;

	if (auto originFuncDef = dynamic_cast<FunctionDefinition const*>(_callable))
		for (auto const* contract: m_currentContract->annotation().linearizedBaseContracts)
		{
				for (auto const* funcDef: contract->definedFunctions())
					if (funcDef->name() == originFuncDef->name())
					{
						FunctionTypePointer fpA = FunctionType(*funcDef).asCallableFunction(false);
						FunctionTypePointer fpB = FunctionType(*originFuncDef).asCallableFunction(false);
						if (fpA->hasEqualReturnTypes(*fpB) && fpA->hasEqualParameterTypes(*fpB))
							return funcDef;
					}
		}
	else if (dynamic_cast<ModifierDefinition const*>(_callable))
		for (auto const* contract: m_currentContract->annotation().linearizedBaseContracts)
			for (auto const* modDef: contract->functionModifiers())
				if (_callable->name() == modDef->name())
					return modDef;

	return _callable;
}

FunctionCallGraphBuilder::CallSet const* FunctionCallGraphBuilder::getGraph(Declaration const* _declaration) const
{
	auto result = m_mapping.find(_declaration);

	if (result == m_mapping.cend())
		return nullptr;

	return &result->second;
}
