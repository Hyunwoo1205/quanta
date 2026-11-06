"""Independent mechanics and shared-kernel boundary checks; no time integration."""
import copy
from fractions import Fraction
import math
import struct

import numpy as np
import pytest

from quanta.autodiff import CalculationError
from quanta.pair import _PreparedPair
from quanta.pair_kernel import PairForceKernel


def harmonic():
    return {"op":"mul","args":[{"op":"const","value":0.375},
             {"op":"pow","arg":{"op":"var","name":"rho"},"exponent":2}]}


def kernel(*, count=2, length_m=1., energy_j=1., min_distance_m=0.1,
           expression=None, parameters=None, **kwargs):
    return PairForceKernel(count=count, length_m=length_m, energy_j=energy_j,
        min_distance_m=min_distance_m, expression=harmonic() if expression is None else expression,
        parameters={} if parameters is None else parameters, **kwargs)


def test_module_independent_three_body_harmonic_matches_fraction_reference():
    positions = [[0.,0.,0.],[2.,0.,0.],[0.,4.,6.]]
    result = kernel(count=3,length_m=2.,energy_j=8.,requested_pairs=True).evaluate(positions)
    # U=0.375*E0/L0² sum(rij²), Fi=-(0.75*E0/L0²)sum_j(ri-rj).
    stiffness = Fraction(3,2)
    q = [[Fraction(x) for x in row] for row in positions]
    reference_energy = sum(stiffness/2 * sum((q[i][a]-q[j][a])**2 for a in range(3))
                           for i in range(3) for j in range(i+1,3))
    reference_forces = [[-stiffness*sum(q[i][a]-q[j][a] for j in range(3) if j != i)
                         for a in range(3)] for i in range(3)]
    assert result.energy_j == pytest.approx(float(reference_energy),rel=2e-14)
    np.testing.assert_allclose(result.forces_n,np.array(reference_forces,dtype=float),rtol=2e-14,atol=1e-14)
    np.testing.assert_allclose(np.sum(result.forces_n,axis=0),[0,0,0],atol=1e-14)
    np.testing.assert_allclose(np.cross(positions,result.forces_n).sum(axis=0),[0,0,0],atol=2e-13)
    assert [(p['i'],p['j']) for p in result.pair_energies] == [(0,1),(0,2),(1,2)]
    assert result.positions == positions


def test_nonquadratic_force_has_independent_central_difference_reference():
    expr = {"op":"add","args":[
        {"op":"exp","arg":{"op":"neg","arg":{"op":"var","name":"rho"}}},
        {"op":"sin","arg":{"op":"var","name":"rho"}}]}
    engine = kernel(expression=expr)
    positions = [[-.2,.3,-.1],[1.3,-.4,.8]]
    result = engine.evaluate(positions)
    def energy(q):
        distance = math.dist(q[0],q[1])
        return math.exp(-distance)+math.sin(distance)
    h=1e-5
    for i in range(2):
        for axis in range(3):
            plus,minus=copy.deepcopy(positions),copy.deepcopy(positions)
            plus[i][axis]+=h;minus[i][axis]-=h
            expected=-(energy(plus)-energy(minus))/(2*h)
            assert result.forces_n[i][axis] == pytest.approx(expected,abs=2e-10,rel=2e-9)


def test_scales_ast_parameters_and_returned_arrays_do_not_alias_caller_data():
    expr={"op":"mul","args":[{"op":"param","name":"k"},{"op":"pow","arg":{"op":"var","name":"rho"},"exponent":2}]}
    parameters={"k":.375}
    positions=[[-1.,0.,-0.],[1.,0.,0.]]
    original=copy.deepcopy(positions)
    engine=kernel(expression=expr,parameters=parameters)
    expected=engine.evaluate(positions)
    expr["args"][0]["name"]="missing"
    parameters["k"]=999
    expected.positions[0][0]=123
    expected.forces_n[0][0]=123
    actual=engine.evaluate(positions)
    assert positions == original
    assert actual.positions == original
    assert actual.energy_j == 1.5
    assert actual.forces_n == [[1.5,0.,0.],[-1.5,0.,0.]]
    assert struct.pack('!d',actual.positions[0][2]) == struct.pack('!d',-0.)


def test_two_scales_represent_same_physical_harmonic_model():
    positions=[[-1.,.25,0.],[2.,-.5,1.]]
    base=kernel().evaluate(positions)
    # Coefficient multiplies by (L_new/L_old)^2/(E_new/E_old).
    transformed=kernel(length_m=2.,energy_j=4.).evaluate(positions)
    assert transformed.energy_j == base.energy_j
    assert transformed.forces_n == base.forces_n


@pytest.mark.parametrize('expression,energy', [({'op':'const','value':0},1e-200),
                                               ({'op':'const','value':0},1e200)])
def test_genuine_zero_energy_and_force_are_not_underflow(expression,energy):
    result=kernel(expression=expression,energy_j=energy).evaluate([[0,0,0],[1,0,0]])
    assert result.energy_j == 0
    assert result.forces_n == [[0,0,0],[0,0,0]]
    assert result.pair_energies == []


@pytest.mark.parametrize('change', [
    {'count':True},{'count':1},{'count':129},{'length_m':0},{'energy_j':-1},
    {'min_distance_m':0},{'energy_j':math.inf},{'requested_pairs':1}])
def test_kernel_rejects_invalid_physical_construction(change):
    with pytest.raises(CalculationError):
        kernel(**change)


@pytest.mark.parametrize('positions', [None,[[0,0]],[[0,0,0],[1,0]],
                                      [[0,0,0],[math.inf,0,0]],[[0,0,0],[True,0,0]]])
def test_kernel_rejects_bad_position_shape_and_carrier(positions):
    with pytest.raises(CalculationError) as caught:
        kernel().evaluate(positions)
    assert caught.value.path.startswith('/system/particles')


@pytest.mark.parametrize('distance',[0,.05,.1])
def test_minimum_distance_is_strict_and_retains_pair_context(distance):
    with pytest.raises(CalculationError) as caught:
        kernel().evaluate([[0,0,0],[distance,0,0]])
    assert caught.value.path == '/system/particles'
    assert caught.value.details['pair_indices'] == [0,1]


def test_ast_domain_errors_use_caller_potential_path_and_exact_pair_context():
    expr={'op':'log','arg':{'op':'sub','args':[{'op':'var','name':'rho'},{'op':'const','value':2}]}}
    with pytest.raises(CalculationError) as caught:
        kernel(expression=expr,potential_path='/request/system/potential').evaluate([[0,0,0],[1,0,0]])
    assert caught.value.path == '/request/system/potential/expression'
    assert caught.value.details['pair_indices'] == [0,1]
    assert caught.value.code == 'EXPRESSION_DOMAIN'


@pytest.mark.parametrize('expression,energy,length', [
    ({'op':'const','value':1e-200},1e-200,1),
    ({'op':'const','value':2},1e308,1),
    ({'op':'mul','args':[{'op':'const','value':2},{'op':'var','name':'rho'}]},1e308,1)])
def test_nonzero_si_range_failure_remains_explicit(expression,energy,length):
    with pytest.raises(CalculationError):
        kernel(expression=expression,energy_j=energy,length_m=length).evaluate([[0,0,0],[1,0,0]])


def test_deadline_callback_order_and_cancellation_interrupt_loop():
    positions=[[0,0,0],[1,0,0],[0,1,0]]
    engine=kernel(count=3)
    checks=[]
    engine.evaluate(positions,check_deadline=lambda:checks.append(len(checks)))
    assert checks == [0,1,2,3]  # before each i<j pair, then after complete aggregation
    class StopNow(Exception):
        pass
    checks=[]
    def cancel():
        checks.append(len(checks))
        if len(checks)==2:
            raise StopNow()
    with pytest.raises(StopNow):
        engine.evaluate(positions,check_deadline=cancel)
    assert checks == [0,1]


def test_static_adapter_keeps_fixed_signed_zero_and_unmasked_raw_force(pair):
    d=copy.deepcopy(pair['definition'])
    d['protocol']['steps']=[{'step_id':'e','operation':'energy_forces','source':'initial','overrides':[]}]
    d['observables']=['energy','forces']
    d['scales']={'length_m':1.,'energy_j':1.}
    d['system']['potential']={'expression':harmonic(),'parameters':{}}
    d['system']['min_distance_m']=.1
    d['system']['particles']=[{'id':'a','position_m':[-1.,-0.,0.],'fixed':[True,True,True]},
                              {'id':'b','position_m':[1.,0.,0.],'fixed':[False,False,False]}]
    prepared=_PreparedPair(d)
    evaluation=prepared.evaluate(prepared.initial_positions)
    assert evaluation.forces_n == [[1.5,0.,0.],[-1.5,0.,0.]]
    assert evaluation.free_gradient_inf == 1.5
    trial=copy.deepcopy(prepared.initial_positions);trial[0][1]=0.
    with pytest.raises(CalculationError) as caught:
        prepared.evaluate(trial)
    assert caught.value.path == '/definition/system/particles/0/position_m/1'
