/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <test/yulPhaser/TestHelpers.h>

#include <tools/yulPhaser/Exceptions.h>
#include <tools/yulPhaser/Phaser.h>

#include <liblangutil/CharStream.h>

#include <libsolutil/CommonIO.h>

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

#include <algorithm>

using namespace std;
using namespace solidity::util;
using namespace solidity::langutil;

namespace fs = boost::filesystem;

namespace solidity::phaser::test
{

class GeneticAlgorithmFactoryFixture
{
protected:
	GeneticAlgorithmFactory::Options m_options = {
		/* algorithm = */ Algorithm::Random,
		/* minChromosomeLength = */ 50,
		/* maxChromosomeLength = */ 100,
		/* randomElitePoolSize = */ 0.5,
		/* gewepMutationPoolSize = */ 0.1,
		/* gewepCrossoverPoolSize = */ 0.1,
		/* gewepRandomisationChance = */ 0.6,
		/* gewepDeletionVsAdditionChance = */ 0.3,
		/* gewepGenesToRandomise = */ 0.4,
		/* gewepGenesToAddOrDelete = */ 0.2,
	};
};

class FitnessMetricFactoryFixture
{
protected:
	CharStream m_sourceStream = CharStream("{}", "");
	Program m_program = get<Program>(Program::load(m_sourceStream));
	FitnessMetricFactory::Options m_options = {
		/* chromosomeRepetitions = */ 1,
	};
};

class PoulationFactoryFixture
{
protected:
	shared_ptr<FitnessMetric> m_fitnessMetric = make_shared<ChromosomeLengthMetric>();
	PopulationFactory::Options m_options = {
		/* minChromosomeLength = */ 0,
		/* maxChromosomeLength = */ 0,
		/* population = */ {},
		/* randomPopulation = */ {},
		/* populationFromFile = */ {},
	};
};

BOOST_AUTO_TEST_SUITE(Phaser)
BOOST_AUTO_TEST_SUITE(PhaserTest)
BOOST_AUTO_TEST_SUITE(GeneticAlgorithmFactoryTest)

BOOST_FIXTURE_TEST_CASE(build_should_select_the_right_algorithm_and_pass_the_options_to_it, GeneticAlgorithmFactoryFixture)
{
	m_options.algorithm = Algorithm::Random;
	unique_ptr<GeneticAlgorithm> algorithm1 = GeneticAlgorithmFactory::build(m_options, 100);
	BOOST_REQUIRE(algorithm1 != nullptr);

	auto randomAlgorithm = dynamic_cast<RandomAlgorithm*>(algorithm1.get());
	BOOST_REQUIRE(randomAlgorithm != nullptr);
	BOOST_TEST(randomAlgorithm->options().elitePoolSize == m_options.randomElitePoolSize.value());
	BOOST_TEST(randomAlgorithm->options().minChromosomeLength == m_options.minChromosomeLength);
	BOOST_TEST(randomAlgorithm->options().maxChromosomeLength == m_options.maxChromosomeLength);

	m_options.algorithm = Algorithm::GEWEP;
	unique_ptr<GeneticAlgorithm> algorithm2 = GeneticAlgorithmFactory::build(m_options, 100);
	BOOST_REQUIRE(algorithm2 != nullptr);

	auto gewepAlgorithm = dynamic_cast<GenerationalElitistWithExclusivePools*>(algorithm2.get());
	BOOST_REQUIRE(gewepAlgorithm != nullptr);
	BOOST_TEST(gewepAlgorithm->options().mutationPoolSize == m_options.gewepMutationPoolSize);
	BOOST_TEST(gewepAlgorithm->options().crossoverPoolSize == m_options.gewepCrossoverPoolSize);
	BOOST_TEST(gewepAlgorithm->options().randomisationChance == m_options.gewepRandomisationChance);
	BOOST_TEST(gewepAlgorithm->options().deletionVsAdditionChance == m_options.gewepDeletionVsAdditionChance);
	BOOST_TEST(gewepAlgorithm->options().percentGenesToRandomise == m_options.gewepGenesToRandomise.value());
	BOOST_TEST(gewepAlgorithm->options().percentGenesToAddOrDelete == m_options.gewepGenesToAddOrDelete.value());
}

BOOST_FIXTURE_TEST_CASE(build_should_set_random_algorithm_elite_pool_size_based_on_population_size_if_not_specified, GeneticAlgorithmFactoryFixture)
{
	m_options.algorithm = Algorithm::Random;
	m_options.randomElitePoolSize = nullopt;
	unique_ptr<GeneticAlgorithm> algorithm = GeneticAlgorithmFactory::build(m_options, 100);
	BOOST_REQUIRE(algorithm != nullptr);

	auto randomAlgorithm = dynamic_cast<RandomAlgorithm*>(algorithm.get());
	BOOST_REQUIRE(randomAlgorithm != nullptr);
	BOOST_TEST(randomAlgorithm->options().elitePoolSize == 1.0 / 100.0);
}

BOOST_FIXTURE_TEST_CASE(build_should_set_gewep_mutation_percentages_based_on_maximum_chromosome_length_if_not_specified, GeneticAlgorithmFactoryFixture)
{
	m_options.algorithm = Algorithm::GEWEP;
	m_options.gewepGenesToRandomise = nullopt;
	m_options.gewepGenesToAddOrDelete = nullopt;
	m_options.maxChromosomeLength = 125;

	unique_ptr<GeneticAlgorithm> algorithm = GeneticAlgorithmFactory::build(m_options, 100);
	BOOST_REQUIRE(algorithm != nullptr);

	auto gewepAlgorithm = dynamic_cast<GenerationalElitistWithExclusivePools*>(algorithm.get());
	BOOST_REQUIRE(gewepAlgorithm != nullptr);
	BOOST_TEST(gewepAlgorithm->options().percentGenesToRandomise == 1.0 / 125.0);
	BOOST_TEST(gewepAlgorithm->options().percentGenesToAddOrDelete == 1.0 / 125.0);
}

BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE(FitnessMetricFactoryTest)

BOOST_FIXTURE_TEST_CASE(build_should_create_metric_of_the_right_type, FitnessMetricFactoryFixture)
{
	unique_ptr<FitnessMetric> metric = FitnessMetricFactory::build(m_options, m_program);
	BOOST_REQUIRE(metric != nullptr);

	auto programSizeMetric = dynamic_cast<ProgramSize*>(metric.get());
	BOOST_REQUIRE(programSizeMetric != nullptr);
	BOOST_TEST(toString(programSizeMetric->program()) == toString(m_program));
}

BOOST_FIXTURE_TEST_CASE(build_should_respect_chromosome_repetitions_option, FitnessMetricFactoryFixture)
{
	m_options.chromosomeRepetitions = 5;
	unique_ptr<FitnessMetric> metric = FitnessMetricFactory::build(m_options, m_program);
	BOOST_REQUIRE(metric != nullptr);

	auto programSizeMetric = dynamic_cast<ProgramSize*>(metric.get());
	BOOST_REQUIRE(programSizeMetric != nullptr);
	BOOST_TEST(programSizeMetric->repetitionCount() == m_options.chromosomeRepetitions);
}

BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE(PopulationFactoryTest)

BOOST_FIXTURE_TEST_CASE(build_should_create_an_empty_population_if_no_specific_options_given, PoulationFactoryFixture)
{
	m_options.population = {};
	m_options.randomPopulation = {};
	m_options.populationFromFile = {};
	BOOST_TEST(
		PopulationFactory::build(m_options, m_fitnessMetric) ==
		Population(m_fitnessMetric, vector<Chromosome>{})
	);
}

BOOST_FIXTURE_TEST_CASE(build_should_respect_population_option, PoulationFactoryFixture)
{
	m_options.population = {"a", "afc", "xadd"};
	BOOST_TEST(
		PopulationFactory::build(m_options, m_fitnessMetric) ==
		Population(m_fitnessMetric, {Chromosome("a"), Chromosome("afc"), Chromosome("xadd")})
	);
}

BOOST_FIXTURE_TEST_CASE(build_should_respect_random_population_option, PoulationFactoryFixture)
{
	m_options.randomPopulation = {5, 3, 2};
	m_options.minChromosomeLength = 5;
	m_options.maxChromosomeLength = 10;

	auto population = PopulationFactory::build(m_options, m_fitnessMetric);

	BOOST_TEST(population.individuals().size() == 10);
	BOOST_TEST(all_of(
		population.individuals().begin(),
		population.individuals().end(),
		[](auto const& individual){ return 5 <= individual.chromosome.length() && individual.chromosome.length() <= 10; }
	));
}

BOOST_FIXTURE_TEST_CASE(build_should_respect_population_from_file_option, PoulationFactoryFixture)
{
	map<string, vector<string>> fileContent = {
		{"a.txt", {"a", "fff", "", "jxccLTa"}},
		{"b.txt", {}},
		{"c.txt", {""}},
		{"d.txt", {"c", "T"}},
	};

	TemporaryDirectory tempDir;
	for (auto const& [fileName, chromosomes]: fileContent)
	{
		ofstream tmpFile(tempDir.memberPath(fileName));
		for (auto const& chromosome: chromosomes)
			tmpFile << chromosome << endl;

		m_options.populationFromFile.push_back(tempDir.memberPath(fileName));
	}

	BOOST_TEST(
		PopulationFactory::build(m_options, m_fitnessMetric) ==
		Population(m_fitnessMetric, {
			Chromosome("a"),
			Chromosome("fff"),
			Chromosome(""),
			Chromosome("jxccLTa"),
			Chromosome(""),
			Chromosome("c"),
			Chromosome("T"),
		})
	);
}

BOOST_FIXTURE_TEST_CASE(build_should_throw_FileOpenError_if_population_file_does_not_exist, PoulationFactoryFixture)
{
	m_options.populationFromFile = {"a-file-that-does-not-exist.abcdefgh"};
	assert(!fs::exists(m_options.populationFromFile[0]));

	BOOST_CHECK_THROW(PopulationFactory::build(m_options, m_fitnessMetric), FileOpenError);
}

BOOST_FIXTURE_TEST_CASE(build_should_combine_populations_from_all_sources, PoulationFactoryFixture)
{
	TemporaryDirectory tempDir;
	{
		ofstream tmpFile(tempDir.memberPath("population.txt"));
		tmpFile << "axc" << endl << "fcL" << endl;
	}

	m_options.population = {"axc", "fcL"};
	m_options.randomPopulation = {2};
	m_options.populationFromFile = {tempDir.memberPath("population.txt")};
	m_options.minChromosomeLength = 3;
	m_options.maxChromosomeLength = 3;

	auto population = PopulationFactory::build(m_options, m_fitnessMetric);

	auto begin = population.individuals().begin();
	auto end = population.individuals().end();
	BOOST_TEST(population.individuals().size() == 6);
	BOOST_TEST(all_of(begin, end, [](auto const& individual){ return individual.chromosome.length() == 3; }));
	BOOST_TEST(count(begin, end, Individual(Chromosome("axc"), *m_fitnessMetric)) >= 2);
	BOOST_TEST(count(begin, end, Individual(Chromosome("fcL"), *m_fitnessMetric)) >= 2);
}

BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE(ProgramFactoryTest)

BOOST_AUTO_TEST_CASE(build_should_load_program_from_file)
{
	TemporaryDirectory tempDir;
	{
		ofstream tmpFile(tempDir.memberPath("program.yul"));
		tmpFile << "{}" << endl;
	}

	ProgramFactory::Options options{/* inputFile = */ tempDir.memberPath("program.yul")};
	CharStream expectedProgramSource("{}", "");

	auto program = ProgramFactory::build(options);

	BOOST_TEST(toString(program) == toString(get<Program>(Program::load(expectedProgramSource))));
}

BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()

}
