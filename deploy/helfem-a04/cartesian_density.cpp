// Quanta development-only density projection for the pinned HelFEM checkpoint.
#include "atomic/TwoDBasis.h"
#include "diatomic/basis.h"
#include "general/checkpoint.h"
#include "general/model_potential.h"
#include <helfem/chebyshev.h>

#include <algorithm>
#include <bit>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numbers>
#include <stdexcept>
#include <vector>

namespace {
constexpr int max_axis = 320;

helfem::Matrix occupied_orbitals(Checkpoint &checkpoint, const helfem::Matrix &overlap) {
  int nela, nelb;
  checkpoint.read("nela", nela);
  checkpoint.read("nelb", nelb);
  if (nela != 1 || nelb != 1)
    throw std::runtime_error("Expected a neutral two-electron singlet checkpoint");

  helfem::Matrix occupied(overlap.rows(), 2);
  for (int spin = 0; spin < 2; ++spin) {
    helfem::Matrix orbitals, density;
    helfem::Vector occupations;
    checkpoint.read(spin == 0 ? "Ca" : "Cb", orbitals);
    checkpoint.read(spin == 0 ? "Pa" : "Pb", density);
    checkpoint.read(spin == 0 ? "occa" : "occb", occupations);
    if (orbitals.rows() != overlap.rows() || orbitals.cols() < 1 ||
        density.rows() != overlap.rows() || density.cols() != overlap.cols() ||
        occupations.size() != orbitals.cols() || !orbitals.allFinite() ||
        !density.allFinite() || !occupations.allFinite() ||
        std::abs(occupations(0) - 1.0) > 1e-12 ||
        occupations.tail(occupations.size() - 1).norm() > 1e-12)
      throw std::runtime_error("Unexpected checkpoint orbital/occupation layout");
    occupied.col(spin) = orbitals.col(0);
    const auto one_orbital_density = occupied.col(spin) * occupied.col(spin).transpose();
    if ((density - one_orbital_density).norm() > 1e-10 * std::max(1.0, density.norm()))
      throw std::runtime_error("Occupied orbital disagrees with checkpoint density matrix");
  }
  // A restricted state permits opposite signs for the two occupied orbitals.
  if (std::abs(std::abs(occupied.col(0).dot(overlap * occupied.col(1))) - 1.0) > 1e-9)
    throw std::runtime_error("The two occupied orbitals do not describe a restricted singlet");
  const double integral = (occupied.transpose() * overlap * occupied).trace();
  if (!std::isfinite(integral) || std::abs(integral - 2.0) > 1e-8)
    throw std::runtime_error("Electron count disagrees with the basis-overlap integral");
  std::cout << "overlap_electrons " << integral << '\n';
  return occupied;
}

class HeliumDensity {
public:
  explicit HeliumDensity(Checkpoint &checkpoint) {
    checkpoint.read(basis_);
    if (basis_.Z() != 2 || basis_.Zl() != 0 || basis_.Zr() != 0 ||
        basis_.nuclear_model() != helfem::modelpotential::POINT_NUCLEUS)
      throw std::runtime_error("Expected isolated point-nucleus He");
    boundaries_ = basis_.bval();
    auto all_occupied = occupied_orbitals(checkpoint, basis_.overlap());
    const auto s_indices = basis_.lm_indices(0, 0);
    if (s_indices.size() != basis_.Nrad())
      throw std::runtime_error("Unexpected He s-wave radial basis layout");
    occupied_ = all_occupied(s_indices, Eigen::all);
    for (const auto index : s_indices)
      all_occupied.row(index).setZero();
    if ((all_occupied.array() != 0.0).any())
      throw std::runtime_error("The occupied He orbitals are not spherical");
  }

  double radius_limit() const { return boundaries_(boundaries_.size() - 1); }
  const helfem::Vector &boundaries() const { return boundaries_; }

  double operator()(double radius) const {
    if (radius >= radius_limit())
      return 0.0; // HelFEM's finite Dirichlet domain.
    const auto *upper = std::upper_bound(boundaries_.data(),
                                         boundaries_.data() + boundaries_.size(), radius);
    const size_t element = upper - boundaries_.data() - 1;
    const double start = boundaries_(element);
    helfem::Vector local(1);
    local(0) = 2.0 * (radius - start) / (boundaries_(element + 1) - start) - 1.0;
    size_t first, last;
    basis_.radial().idx(element, first, last);
    return (basis_.radial().bf(local, element) * occupied_.middleRows(first, last - first + 1))
               .squaredNorm() / (4.0 * std::numbers::pi);
  }

private:
  helfem::atomic::basis::TwoDBasis basis_;
  helfem::Vector boundaries_;
  helfem::Matrix occupied_;
};

class HydrogenDensity {
public:
  HydrogenDensity(Checkpoint &checkpoint, double bond) : half_(bond / 2) {
    checkpoint.read(basis_);
    if (basis_.Z1() != 1 || basis_.Z2() != 1 ||
        std::abs(basis_.Rhalf() - half_) > 1e-13)
      throw std::runtime_error("Checkpoint nuclei do not match the exact H2 bond geometry");
    half_ = basis_.Rhalf();
    boundaries_ = basis_.bval();
    occupied_ = occupied_orbitals(checkpoint, basis_.overlap());
    const auto indices = basis_.m_indices(0);
    helfem::Matrix other = occupied_;
    for (const auto index : indices)
      other.row(index).setZero();
    if ((other.array() != 0.0).any())
      throw std::runtime_error("The occupied H2 orbitals are not axisymmetric");
  }

  const helfem::Vector &boundaries() const { return boundaries_; }
  double half_bond() const { return half_; }
  double axial_limit() const { return half_ * std::cosh(boundaries_(boundaries_.size() - 1)); }

  double operator()(double axial, double radius) const {
    // The CUBE x-axis bond maps to the HelFEM z-axis. Distances are
    // from the negative and positive nuclei respectively.
    const double rminus = std::hypot(radius, axial + half_);
    const double rplus = std::hypot(radius, axial - half_);
    const double xi = std::max(1.0, (rminus + rplus) / (2.0 * half_));
    const double eta = std::clamp(axial / (half_ * xi), -1.0, 1.0);
    return prolate(std::acosh(xi), eta);
  }

  double prolate(double mu, double eta) const {
    if (mu >= boundaries_(boundaries_.size() - 1))
      return 0.0;
    const auto values = basis_.eval_bf(mu, eta, 0.0);
    return (values.transpose() * occupied_).squaredNorm();
  }

private:
  helfem::diatomic::basis::TwoDBasis basis_;
  double half_;
  helfem::Vector boundaries_;
  helfem::Matrix occupied_;
};

template<typename Integrand>
double integrate_elements(const helfem::Vector &boundaries, double lower, const helfem::Vector &nodes,
                          const helfem::Vector &weights, Integrand evaluate) {
  double result = 0.0;
  for (Eigen::Index i = 0; i < boundaries.size() - 1; ++i) {
    const double start = std::max(lower, boundaries(i));
    const double end = boundaries(i + 1);
    if (start >= end)
      continue;
    const double half = (end - start) / 2.0;
    for (Eigen::Index j = 0; j < nodes.size(); ++j)
      result += half * weights(j) * evaluate(start + half * (1.0 + nodes(j)));
  }
  return result;
}

template<typename Integrand>
void report_integrals(const helfem::Vector &boundaries, double enclosed_limit, Integrand evaluate) {
  for (const int order : {32, 64}) {
    helfem::Vector nodes, weights;
    helfem::chebyshev::chebyshev(order, nodes, weights);
    const auto radial = [&](double r) { return evaluate(r, nodes, weights); };
    std::cout << "quadrature_" << order << "_electrons "
              << integrate_elements(boundaries, 0.0, nodes, weights, radial) << '\n';
    std::cout << "cell_omitted_upper_" << order << "_electrons "
              << integrate_elements(boundaries, enclosed_limit, nodes, weights, radial) << '\n';
  }
}

template<typename Density>
double cache_value(std::vector<double> &cache, int key, Density evaluate) {
  if (std::isnan(cache[key]))
    cache[key] = evaluate();
  return cache[key];
}

template<typename Density>
void write_grid(std::ofstream &output, int count, Density evaluate) {
  std::vector<double> row(count);
  const int half_count = count / 2;
  for (int x = -half_count; x < half_count; ++x) {
    for (int y = -half_count; y < half_count; ++y) {
      for (int z = -half_count; z < half_count; ++z) {
        const double value = evaluate(x, y, z);
        if (!std::isfinite(value))
          throw std::runtime_error("Nonfinite finite-element sample");
        row[z + half_count] = value;
      }
      output.write(reinterpret_cast<const char *>(row.data()), count * sizeof(double));
    }
  }
}

void export_grid(Checkpoint &checkpoint, std::ofstream &output, int count, double cell, double bond) {
  const double spacing = cell / count;
  const int plane_size = count * count / 2 + 1;
  const double unset = std::numeric_limits<double>::quiet_NaN();
  if (bond == 0.0) {
    const HeliumDensity rho(checkpoint);
    std::cout << "finite_domain_axial_bohr " << rho.radius_limit() << '\n';
    report_integrals(rho.boundaries(), cell / 2, [&](double r, const auto &, const auto &) {
      return 4.0 * std::numbers::pi * r * r * rho(r);
    });
    std::vector<double> cache(3 * count * count / 4 + 1, unset);
    write_grid(output, count, [&](int x, int y, int z) {
      const int radius_squared = x*x + y*y + z*z;
      return cache_value(cache, radius_squared, [&] { return rho(spacing * std::sqrt(radius_squared)); });
    });
    return;
  }

  const HydrogenDensity rho(checkpoint, bond);
  std::cout << "finite_domain_axial_bohr " << rho.axial_limit() << '\n';
  const double a = rho.half_bond();
  report_integrals(rho.boundaries(), std::acosh(cell / (2.0 * a)),
    [&](double mu, const auto &nodes, const auto &weights) {
      const double cosh_mu = std::cosh(mu);
      double angular = 0.0;
      for (Eigen::Index j = 0; j < nodes.size(); ++j) {
        const double eta = nodes(j);
        angular += weights(j) * (cosh_mu*cosh_mu - eta*eta) * rho.prolate(mu, eta);
      }
      return 2.0 * std::numbers::pi * a*a*a * std::sinh(mu) * angular;
    });
  int previous_x = -count;
  std::vector<double> cache(plane_size, unset);
  write_grid(output, count, [&](int x, int y, int z) {
    if (x != previous_x) {
      std::fill(cache.begin(), cache.end(), unset);
      previous_x = x;
    }
    const int radius_squared = y*y + z*z;
    return cache_value(cache, radius_squared, [&] {
      return rho(x * spacing, spacing * std::sqrt(radius_squared));
    });
  });
}
} // namespace

int main(int argc, char **argv) {
  static_assert(sizeof(double) == 8 && std::numeric_limits<double>::is_iec559 &&
                std::endian::native == std::endian::little);
  try {
    if (argc != 6)
      throw std::runtime_error("Usage: a04_helfem_cartesian checkpoint.h5 output.f64 axis_count cell_bohr bond_bohr");
    size_t count_end, cell_end, bond_end;
    const int count = std::stoi(argv[3], &count_end);
    const double cell = std::stod(argv[4], &cell_end);
    const double bond = std::stod(argv[5], &bond_end);
    if (argv[3][count_end] || argv[4][cell_end] || argv[5][bond_end] ||
        count < 2 || count > max_axis || count % 2 != 0 ||
        !std::isfinite(cell) || !std::isfinite(bond) || bond < 0.0 || cell <= bond)
      throw std::runtime_error("Expected a bounded even grid and valid exact Bohr geometry");
    Checkpoint checkpoint(argv[1], false);
    std::ofstream output;
    output.exceptions(std::ios::badbit | std::ios::failbit);
    output.open(argv[2], std::ios::binary);
    std::cout << std::setprecision(17);
    export_grid(checkpoint, output, count, cell, bond);
    output.close();
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
}
