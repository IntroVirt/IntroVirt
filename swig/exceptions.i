/* Catch C++ exceptions and convert to Python exceptions (most specific first) */
%exception {
  try {
    $action
  }
  catch (introvirt::NoSuchDomainException& e) {
    PyErr_SetString(p_NoSuchDomainException, e.what());
    SWIG_fail;
  }
  catch (introvirt::DomainBusyException& e) {
    PyErr_SetString(p_DomainBusyException, e.what());
    SWIG_fail;
  }
  catch (introvirt::UnsupportedHypervisorException& e) {
    PyErr_SetString(p_UnsupportedHypervisorException, e.what());
    SWIG_fail;
  }
  catch (introvirt::GuestDetectionException& e) {
    PyErr_SetString(p_GuestDetectionException, e.what());
    SWIG_fail;
  }
  catch (introvirt::InvalidMethodException& e) {
    PyErr_SetString(p_InvalidMethodException, e.what());
    SWIG_fail;
  }
  catch (introvirt::InvalidVcpuException& e) {
    PyErr_SetString(p_InvalidVcpuException, e.what());
    SWIG_fail;
  }
  catch (introvirt::NotImplementedException& e) {
    PyErr_SetString(p_NotImplementedException, e.what());
    SWIG_fail;
  }
  catch (introvirt::CommandFailedException& e) {
    PyErr_SetString(p_CommandFailedException, e.what());
    SWIG_fail;
  }
  catch (introvirt::BadPhysicalAddressException& e) {
    PyErr_SetString(p_BadPhysicalAddressException, e.what());
    SWIG_fail;
  }
  catch (introvirt::VirtualAddressNotPresentException& e) {
    PyErr_SetString(p_VirtualAddressNotPresentException, e.what());
    SWIG_fail;
  }
  catch (introvirt::windows::pe::PeException& e) {
    PyErr_SetString(p_PeException, e.what());
    SWIG_fail;
  }
  catch (introvirt::TraceableException& e) {
    PyErr_SetString(p_IntroVirtError, e.what());
    SWIG_fail;
  }
  SWIG_CATCH_STDEXCEPT
  catch (...) {
    SWIG_exception(SWIG_UnknownError, "unknown exception");
  }
}
