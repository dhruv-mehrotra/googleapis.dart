library googleapis.analytics.v3.test;

import "dart:core" as core;
import "dart:collection" as collection;
import "dart:async" as async;
import "dart:convert" as convert;

import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_testing;
import 'package:unittest/unittest.dart' as unittest;

import 'package:googleapis/analytics/v3.dart' as api;

class HttpServerMock extends http.BaseClient {
  core.Function _callback;
  core.bool _expectJson;

  void register(core.Function callback, core.bool expectJson) {
    _callback = callback;
    _expectJson = expectJson;
  }

  async.Future<http.StreamedResponse> send(http.BaseRequest request) {
    if (_expectJson) {
      return request.finalize()
          .transform(convert.UTF8.decoder)
          .join('')
          .then((core.String jsonString) {
        if (jsonString.isEmpty) {
          return _callback(request, null);
        } else {
          return _callback(request, convert.JSON.decode(jsonString));
        }
      });
    } else {
      var stream = request.finalize();
      if (stream == null) {
        return _callback(request, []);
      } else {
        return stream.toBytes().then((data) {
          return _callback(request, data);
        });
      }
    }
  }
}

http.StreamedResponse stringResponse(
    core.int status, core.Map headers, core.String body) {
  var stream = new async.Stream.fromIterable([convert.UTF8.encode(body)]);
  return new http.StreamedResponse(stream, status, headers: headers);
}

core.int buildCounterAccountChildLink = 0;
buildAccountChildLink() {
  var o = new api.AccountChildLink();
  buildCounterAccountChildLink++;
  if (buildCounterAccountChildLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterAccountChildLink--;
  return o;
}

checkAccountChildLink(api.AccountChildLink o) {
  buildCounterAccountChildLink++;
  if (buildCounterAccountChildLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterAccountChildLink--;
}

buildUnnamed877() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed877(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterAccountPermissions = 0;
buildAccountPermissions() {
  var o = new api.AccountPermissions();
  buildCounterAccountPermissions++;
  if (buildCounterAccountPermissions < 3) {
    o.effective = buildUnnamed877();
  }
  buildCounterAccountPermissions--;
  return o;
}

checkAccountPermissions(api.AccountPermissions o) {
  buildCounterAccountPermissions++;
  if (buildCounterAccountPermissions < 3) {
    checkUnnamed877(o.effective);
  }
  buildCounterAccountPermissions--;
}

core.int buildCounterAccount = 0;
buildAccount() {
  var o = new api.Account();
  buildCounterAccount++;
  if (buildCounterAccount < 3) {
    o.childLink = buildAccountChildLink();
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.id = "foo";
    o.kind = "foo";
    o.name = "foo";
    o.permissions = buildAccountPermissions();
    o.selfLink = "foo";
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
  }
  buildCounterAccount--;
  return o;
}

checkAccount(api.Account o) {
  buildCounterAccount++;
  if (buildCounterAccount < 3) {
    checkAccountChildLink(o.childLink);
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    checkAccountPermissions(o.permissions);
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
  }
  buildCounterAccount--;
}

core.int buildCounterAccountRef = 0;
buildAccountRef() {
  var o = new api.AccountRef();
  buildCounterAccountRef++;
  if (buildCounterAccountRef < 3) {
    o.href = "foo";
    o.id = "foo";
    o.kind = "foo";
    o.name = "foo";
  }
  buildCounterAccountRef--;
  return o;
}

checkAccountRef(api.AccountRef o) {
  buildCounterAccountRef++;
  if (buildCounterAccountRef < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
  }
  buildCounterAccountRef--;
}

buildUnnamed878() {
  var o = new core.List<api.AccountSummary>();
  o.add(buildAccountSummary());
  o.add(buildAccountSummary());
  return o;
}

checkUnnamed878(core.List<api.AccountSummary> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkAccountSummary(o[0]);
  checkAccountSummary(o[1]);
}

core.int buildCounterAccountSummaries = 0;
buildAccountSummaries() {
  var o = new api.AccountSummaries();
  buildCounterAccountSummaries++;
  if (buildCounterAccountSummaries < 3) {
    o.items = buildUnnamed878();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterAccountSummaries--;
  return o;
}

checkAccountSummaries(api.AccountSummaries o) {
  buildCounterAccountSummaries++;
  if (buildCounterAccountSummaries < 3) {
    checkUnnamed878(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterAccountSummaries--;
}

buildUnnamed879() {
  var o = new core.List<api.WebPropertySummary>();
  o.add(buildWebPropertySummary());
  o.add(buildWebPropertySummary());
  return o;
}

checkUnnamed879(core.List<api.WebPropertySummary> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkWebPropertySummary(o[0]);
  checkWebPropertySummary(o[1]);
}

core.int buildCounterAccountSummary = 0;
buildAccountSummary() {
  var o = new api.AccountSummary();
  buildCounterAccountSummary++;
  if (buildCounterAccountSummary < 3) {
    o.id = "foo";
    o.kind = "foo";
    o.name = "foo";
    o.webProperties = buildUnnamed879();
  }
  buildCounterAccountSummary--;
  return o;
}

checkAccountSummary(api.AccountSummary o) {
  buildCounterAccountSummary++;
  if (buildCounterAccountSummary < 3) {
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    checkUnnamed879(o.webProperties);
  }
  buildCounterAccountSummary--;
}

core.int buildCounterAccountTicket = 0;
buildAccountTicket() {
  var o = new api.AccountTicket();
  buildCounterAccountTicket++;
  if (buildCounterAccountTicket < 3) {
    o.account = buildAccount();
    o.id = "foo";
    o.kind = "foo";
    o.profile = buildProfile();
    o.redirectUri = "foo";
    o.webproperty = buildWebproperty();
  }
  buildCounterAccountTicket--;
  return o;
}

checkAccountTicket(api.AccountTicket o) {
  buildCounterAccountTicket++;
  if (buildCounterAccountTicket < 3) {
    checkAccount(o.account);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    checkProfile(o.profile);
    unittest.expect(o.redirectUri, unittest.equals('foo'));
    checkWebproperty(o.webproperty);
  }
  buildCounterAccountTicket--;
}

buildUnnamed880() {
  var o = new core.List<api.Account>();
  o.add(buildAccount());
  o.add(buildAccount());
  return o;
}

checkUnnamed880(core.List<api.Account> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkAccount(o[0]);
  checkAccount(o[1]);
}

core.int buildCounterAccounts = 0;
buildAccounts() {
  var o = new api.Accounts();
  buildCounterAccounts++;
  if (buildCounterAccounts < 3) {
    o.items = buildUnnamed880();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterAccounts--;
  return o;
}

checkAccounts(api.Accounts o) {
  buildCounterAccounts++;
  if (buildCounterAccounts < 3) {
    checkUnnamed880(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterAccounts--;
}

core.int buildCounterAdWordsAccount = 0;
buildAdWordsAccount() {
  var o = new api.AdWordsAccount();
  buildCounterAdWordsAccount++;
  if (buildCounterAdWordsAccount < 3) {
    o.autoTaggingEnabled = true;
    o.customerId = "foo";
    o.kind = "foo";
  }
  buildCounterAdWordsAccount--;
  return o;
}

checkAdWordsAccount(api.AdWordsAccount o) {
  buildCounterAdWordsAccount++;
  if (buildCounterAdWordsAccount < 3) {
    unittest.expect(o.autoTaggingEnabled, unittest.isTrue);
    unittest.expect(o.customerId, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
  }
  buildCounterAdWordsAccount--;
}

buildUnnamed881() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed881(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterAnalyticsDataimportDeleteUploadDataRequest = 0;
buildAnalyticsDataimportDeleteUploadDataRequest() {
  var o = new api.AnalyticsDataimportDeleteUploadDataRequest();
  buildCounterAnalyticsDataimportDeleteUploadDataRequest++;
  if (buildCounterAnalyticsDataimportDeleteUploadDataRequest < 3) {
    o.customDataImportUids = buildUnnamed881();
  }
  buildCounterAnalyticsDataimportDeleteUploadDataRequest--;
  return o;
}

checkAnalyticsDataimportDeleteUploadDataRequest(api.AnalyticsDataimportDeleteUploadDataRequest o) {
  buildCounterAnalyticsDataimportDeleteUploadDataRequest++;
  if (buildCounterAnalyticsDataimportDeleteUploadDataRequest < 3) {
    checkUnnamed881(o.customDataImportUids);
  }
  buildCounterAnalyticsDataimportDeleteUploadDataRequest--;
}

buildUnnamed882() {
  var o = new core.Map<core.String, core.String>();
  o["x"] = "foo";
  o["y"] = "foo";
  return o;
}

checkUnnamed882(core.Map<core.String, core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o["x"], unittest.equals('foo'));
  unittest.expect(o["y"], unittest.equals('foo'));
}

core.int buildCounterColumn = 0;
buildColumn() {
  var o = new api.Column();
  buildCounterColumn++;
  if (buildCounterColumn < 3) {
    o.attributes = buildUnnamed882();
    o.id = "foo";
    o.kind = "foo";
  }
  buildCounterColumn--;
  return o;
}

checkColumn(api.Column o) {
  buildCounterColumn++;
  if (buildCounterColumn < 3) {
    checkUnnamed882(o.attributes);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
  }
  buildCounterColumn--;
}

buildUnnamed883() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed883(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

buildUnnamed884() {
  var o = new core.List<api.Column>();
  o.add(buildColumn());
  o.add(buildColumn());
  return o;
}

checkUnnamed884(core.List<api.Column> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkColumn(o[0]);
  checkColumn(o[1]);
}

core.int buildCounterColumns = 0;
buildColumns() {
  var o = new api.Columns();
  buildCounterColumns++;
  if (buildCounterColumns < 3) {
    o.attributeNames = buildUnnamed883();
    o.etag = "foo";
    o.items = buildUnnamed884();
    o.kind = "foo";
    o.totalResults = 42;
  }
  buildCounterColumns--;
  return o;
}

checkColumns(api.Columns o) {
  buildCounterColumns++;
  if (buildCounterColumns < 3) {
    checkUnnamed883(o.attributeNames);
    unittest.expect(o.etag, unittest.equals('foo'));
    checkUnnamed884(o.items);
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.totalResults, unittest.equals(42));
  }
  buildCounterColumns--;
}

core.int buildCounterCustomDataSourceChildLink = 0;
buildCustomDataSourceChildLink() {
  var o = new api.CustomDataSourceChildLink();
  buildCounterCustomDataSourceChildLink++;
  if (buildCounterCustomDataSourceChildLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterCustomDataSourceChildLink--;
  return o;
}

checkCustomDataSourceChildLink(api.CustomDataSourceChildLink o) {
  buildCounterCustomDataSourceChildLink++;
  if (buildCounterCustomDataSourceChildLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterCustomDataSourceChildLink--;
}

core.int buildCounterCustomDataSourceParentLink = 0;
buildCustomDataSourceParentLink() {
  var o = new api.CustomDataSourceParentLink();
  buildCounterCustomDataSourceParentLink++;
  if (buildCounterCustomDataSourceParentLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterCustomDataSourceParentLink--;
  return o;
}

checkCustomDataSourceParentLink(api.CustomDataSourceParentLink o) {
  buildCounterCustomDataSourceParentLink++;
  if (buildCounterCustomDataSourceParentLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterCustomDataSourceParentLink--;
}

buildUnnamed885() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed885(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterCustomDataSource = 0;
buildCustomDataSource() {
  var o = new api.CustomDataSource();
  buildCounterCustomDataSource++;
  if (buildCounterCustomDataSource < 3) {
    o.accountId = "foo";
    o.childLink = buildCustomDataSourceChildLink();
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.description = "foo";
    o.id = "foo";
    o.importBehavior = "foo";
    o.kind = "foo";
    o.name = "foo";
    o.parentLink = buildCustomDataSourceParentLink();
    o.profilesLinked = buildUnnamed885();
    o.selfLink = "foo";
    o.type = "foo";
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
    o.uploadType = "foo";
    o.webPropertyId = "foo";
  }
  buildCounterCustomDataSource--;
  return o;
}

checkCustomDataSource(api.CustomDataSource o) {
  buildCounterCustomDataSource++;
  if (buildCounterCustomDataSource < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    checkCustomDataSourceChildLink(o.childLink);
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.description, unittest.equals('foo'));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.importBehavior, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    checkCustomDataSourceParentLink(o.parentLink);
    checkUnnamed885(o.profilesLinked);
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.uploadType, unittest.equals('foo'));
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
  }
  buildCounterCustomDataSource--;
}

buildUnnamed886() {
  var o = new core.List<api.CustomDataSource>();
  o.add(buildCustomDataSource());
  o.add(buildCustomDataSource());
  return o;
}

checkUnnamed886(core.List<api.CustomDataSource> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkCustomDataSource(o[0]);
  checkCustomDataSource(o[1]);
}

core.int buildCounterCustomDataSources = 0;
buildCustomDataSources() {
  var o = new api.CustomDataSources();
  buildCounterCustomDataSources++;
  if (buildCounterCustomDataSources < 3) {
    o.items = buildUnnamed886();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterCustomDataSources--;
  return o;
}

checkCustomDataSources(api.CustomDataSources o) {
  buildCounterCustomDataSources++;
  if (buildCounterCustomDataSources < 3) {
    checkUnnamed886(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterCustomDataSources--;
}

core.int buildCounterCustomDimensionParentLink = 0;
buildCustomDimensionParentLink() {
  var o = new api.CustomDimensionParentLink();
  buildCounterCustomDimensionParentLink++;
  if (buildCounterCustomDimensionParentLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterCustomDimensionParentLink--;
  return o;
}

checkCustomDimensionParentLink(api.CustomDimensionParentLink o) {
  buildCounterCustomDimensionParentLink++;
  if (buildCounterCustomDimensionParentLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterCustomDimensionParentLink--;
}

core.int buildCounterCustomDimension = 0;
buildCustomDimension() {
  var o = new api.CustomDimension();
  buildCounterCustomDimension++;
  if (buildCounterCustomDimension < 3) {
    o.accountId = "foo";
    o.active = true;
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.id = "foo";
    o.index = 42;
    o.kind = "foo";
    o.name = "foo";
    o.parentLink = buildCustomDimensionParentLink();
    o.scope = "foo";
    o.selfLink = "foo";
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
    o.webPropertyId = "foo";
  }
  buildCounterCustomDimension--;
  return o;
}

checkCustomDimension(api.CustomDimension o) {
  buildCounterCustomDimension++;
  if (buildCounterCustomDimension < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.active, unittest.isTrue);
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.index, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    checkCustomDimensionParentLink(o.parentLink);
    unittest.expect(o.scope, unittest.equals('foo'));
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
  }
  buildCounterCustomDimension--;
}

buildUnnamed887() {
  var o = new core.List<api.CustomDimension>();
  o.add(buildCustomDimension());
  o.add(buildCustomDimension());
  return o;
}

checkUnnamed887(core.List<api.CustomDimension> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkCustomDimension(o[0]);
  checkCustomDimension(o[1]);
}

core.int buildCounterCustomDimensions = 0;
buildCustomDimensions() {
  var o = new api.CustomDimensions();
  buildCounterCustomDimensions++;
  if (buildCounterCustomDimensions < 3) {
    o.items = buildUnnamed887();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterCustomDimensions--;
  return o;
}

checkCustomDimensions(api.CustomDimensions o) {
  buildCounterCustomDimensions++;
  if (buildCounterCustomDimensions < 3) {
    checkUnnamed887(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterCustomDimensions--;
}

core.int buildCounterCustomMetricParentLink = 0;
buildCustomMetricParentLink() {
  var o = new api.CustomMetricParentLink();
  buildCounterCustomMetricParentLink++;
  if (buildCounterCustomMetricParentLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterCustomMetricParentLink--;
  return o;
}

checkCustomMetricParentLink(api.CustomMetricParentLink o) {
  buildCounterCustomMetricParentLink++;
  if (buildCounterCustomMetricParentLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterCustomMetricParentLink--;
}

core.int buildCounterCustomMetric = 0;
buildCustomMetric() {
  var o = new api.CustomMetric();
  buildCounterCustomMetric++;
  if (buildCounterCustomMetric < 3) {
    o.accountId = "foo";
    o.active = true;
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.id = "foo";
    o.index = 42;
    o.kind = "foo";
    o.maxValue = "foo";
    o.minValue = "foo";
    o.name = "foo";
    o.parentLink = buildCustomMetricParentLink();
    o.scope = "foo";
    o.selfLink = "foo";
    o.type = "foo";
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
    o.webPropertyId = "foo";
  }
  buildCounterCustomMetric--;
  return o;
}

checkCustomMetric(api.CustomMetric o) {
  buildCounterCustomMetric++;
  if (buildCounterCustomMetric < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.active, unittest.isTrue);
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.index, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.maxValue, unittest.equals('foo'));
    unittest.expect(o.minValue, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    checkCustomMetricParentLink(o.parentLink);
    unittest.expect(o.scope, unittest.equals('foo'));
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
  }
  buildCounterCustomMetric--;
}

buildUnnamed888() {
  var o = new core.List<api.CustomMetric>();
  o.add(buildCustomMetric());
  o.add(buildCustomMetric());
  return o;
}

checkUnnamed888(core.List<api.CustomMetric> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkCustomMetric(o[0]);
  checkCustomMetric(o[1]);
}

core.int buildCounterCustomMetrics = 0;
buildCustomMetrics() {
  var o = new api.CustomMetrics();
  buildCounterCustomMetrics++;
  if (buildCounterCustomMetrics < 3) {
    o.items = buildUnnamed888();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterCustomMetrics--;
  return o;
}

checkCustomMetrics(api.CustomMetrics o) {
  buildCounterCustomMetrics++;
  if (buildCounterCustomMetrics < 3) {
    checkUnnamed888(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterCustomMetrics--;
}

buildUnnamed889() {
  var o = new core.List<api.AdWordsAccount>();
  o.add(buildAdWordsAccount());
  o.add(buildAdWordsAccount());
  return o;
}

checkUnnamed889(core.List<api.AdWordsAccount> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkAdWordsAccount(o[0]);
  checkAdWordsAccount(o[1]);
}

core.int buildCounterEntityAdWordsLinkEntity = 0;
buildEntityAdWordsLinkEntity() {
  var o = new api.EntityAdWordsLinkEntity();
  buildCounterEntityAdWordsLinkEntity++;
  if (buildCounterEntityAdWordsLinkEntity < 3) {
    o.webPropertyRef = buildWebPropertyRef();
  }
  buildCounterEntityAdWordsLinkEntity--;
  return o;
}

checkEntityAdWordsLinkEntity(api.EntityAdWordsLinkEntity o) {
  buildCounterEntityAdWordsLinkEntity++;
  if (buildCounterEntityAdWordsLinkEntity < 3) {
    checkWebPropertyRef(o.webPropertyRef);
  }
  buildCounterEntityAdWordsLinkEntity--;
}

buildUnnamed890() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed890(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterEntityAdWordsLink = 0;
buildEntityAdWordsLink() {
  var o = new api.EntityAdWordsLink();
  buildCounterEntityAdWordsLink++;
  if (buildCounterEntityAdWordsLink < 3) {
    o.adWordsAccounts = buildUnnamed889();
    o.entity = buildEntityAdWordsLinkEntity();
    o.id = "foo";
    o.kind = "foo";
    o.name = "foo";
    o.profileIds = buildUnnamed890();
    o.selfLink = "foo";
  }
  buildCounterEntityAdWordsLink--;
  return o;
}

checkEntityAdWordsLink(api.EntityAdWordsLink o) {
  buildCounterEntityAdWordsLink++;
  if (buildCounterEntityAdWordsLink < 3) {
    checkUnnamed889(o.adWordsAccounts);
    checkEntityAdWordsLinkEntity(o.entity);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    checkUnnamed890(o.profileIds);
    unittest.expect(o.selfLink, unittest.equals('foo'));
  }
  buildCounterEntityAdWordsLink--;
}

buildUnnamed891() {
  var o = new core.List<api.EntityAdWordsLink>();
  o.add(buildEntityAdWordsLink());
  o.add(buildEntityAdWordsLink());
  return o;
}

checkUnnamed891(core.List<api.EntityAdWordsLink> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkEntityAdWordsLink(o[0]);
  checkEntityAdWordsLink(o[1]);
}

core.int buildCounterEntityAdWordsLinks = 0;
buildEntityAdWordsLinks() {
  var o = new api.EntityAdWordsLinks();
  buildCounterEntityAdWordsLinks++;
  if (buildCounterEntityAdWordsLinks < 3) {
    o.items = buildUnnamed891();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
  }
  buildCounterEntityAdWordsLinks--;
  return o;
}

checkEntityAdWordsLinks(api.EntityAdWordsLinks o) {
  buildCounterEntityAdWordsLinks++;
  if (buildCounterEntityAdWordsLinks < 3) {
    checkUnnamed891(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
  }
  buildCounterEntityAdWordsLinks--;
}

core.int buildCounterEntityUserLinkEntity = 0;
buildEntityUserLinkEntity() {
  var o = new api.EntityUserLinkEntity();
  buildCounterEntityUserLinkEntity++;
  if (buildCounterEntityUserLinkEntity < 3) {
    o.accountRef = buildAccountRef();
    o.profileRef = buildProfileRef();
    o.webPropertyRef = buildWebPropertyRef();
  }
  buildCounterEntityUserLinkEntity--;
  return o;
}

checkEntityUserLinkEntity(api.EntityUserLinkEntity o) {
  buildCounterEntityUserLinkEntity++;
  if (buildCounterEntityUserLinkEntity < 3) {
    checkAccountRef(o.accountRef);
    checkProfileRef(o.profileRef);
    checkWebPropertyRef(o.webPropertyRef);
  }
  buildCounterEntityUserLinkEntity--;
}

buildUnnamed892() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed892(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

buildUnnamed893() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed893(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterEntityUserLinkPermissions = 0;
buildEntityUserLinkPermissions() {
  var o = new api.EntityUserLinkPermissions();
  buildCounterEntityUserLinkPermissions++;
  if (buildCounterEntityUserLinkPermissions < 3) {
    o.effective = buildUnnamed892();
    o.local = buildUnnamed893();
  }
  buildCounterEntityUserLinkPermissions--;
  return o;
}

checkEntityUserLinkPermissions(api.EntityUserLinkPermissions o) {
  buildCounterEntityUserLinkPermissions++;
  if (buildCounterEntityUserLinkPermissions < 3) {
    checkUnnamed892(o.effective);
    checkUnnamed893(o.local);
  }
  buildCounterEntityUserLinkPermissions--;
}

core.int buildCounterEntityUserLink = 0;
buildEntityUserLink() {
  var o = new api.EntityUserLink();
  buildCounterEntityUserLink++;
  if (buildCounterEntityUserLink < 3) {
    o.entity = buildEntityUserLinkEntity();
    o.id = "foo";
    o.kind = "foo";
    o.permissions = buildEntityUserLinkPermissions();
    o.selfLink = "foo";
    o.userRef = buildUserRef();
  }
  buildCounterEntityUserLink--;
  return o;
}

checkEntityUserLink(api.EntityUserLink o) {
  buildCounterEntityUserLink++;
  if (buildCounterEntityUserLink < 3) {
    checkEntityUserLinkEntity(o.entity);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    checkEntityUserLinkPermissions(o.permissions);
    unittest.expect(o.selfLink, unittest.equals('foo'));
    checkUserRef(o.userRef);
  }
  buildCounterEntityUserLink--;
}

buildUnnamed894() {
  var o = new core.List<api.EntityUserLink>();
  o.add(buildEntityUserLink());
  o.add(buildEntityUserLink());
  return o;
}

checkUnnamed894(core.List<api.EntityUserLink> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkEntityUserLink(o[0]);
  checkEntityUserLink(o[1]);
}

core.int buildCounterEntityUserLinks = 0;
buildEntityUserLinks() {
  var o = new api.EntityUserLinks();
  buildCounterEntityUserLinks++;
  if (buildCounterEntityUserLinks < 3) {
    o.items = buildUnnamed894();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
  }
  buildCounterEntityUserLinks--;
  return o;
}

checkEntityUserLinks(api.EntityUserLinks o) {
  buildCounterEntityUserLinks++;
  if (buildCounterEntityUserLinks < 3) {
    checkUnnamed894(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
  }
  buildCounterEntityUserLinks--;
}

core.int buildCounterExperimentParentLink = 0;
buildExperimentParentLink() {
  var o = new api.ExperimentParentLink();
  buildCounterExperimentParentLink++;
  if (buildCounterExperimentParentLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterExperimentParentLink--;
  return o;
}

checkExperimentParentLink(api.ExperimentParentLink o) {
  buildCounterExperimentParentLink++;
  if (buildCounterExperimentParentLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterExperimentParentLink--;
}

core.int buildCounterExperimentVariations = 0;
buildExperimentVariations() {
  var o = new api.ExperimentVariations();
  buildCounterExperimentVariations++;
  if (buildCounterExperimentVariations < 3) {
    o.name = "foo";
    o.status = "foo";
    o.url = "foo";
    o.weight = 42.0;
    o.won = true;
  }
  buildCounterExperimentVariations--;
  return o;
}

checkExperimentVariations(api.ExperimentVariations o) {
  buildCounterExperimentVariations++;
  if (buildCounterExperimentVariations < 3) {
    unittest.expect(o.name, unittest.equals('foo'));
    unittest.expect(o.status, unittest.equals('foo'));
    unittest.expect(o.url, unittest.equals('foo'));
    unittest.expect(o.weight, unittest.equals(42.0));
    unittest.expect(o.won, unittest.isTrue);
  }
  buildCounterExperimentVariations--;
}

buildUnnamed895() {
  var o = new core.List<api.ExperimentVariations>();
  o.add(buildExperimentVariations());
  o.add(buildExperimentVariations());
  return o;
}

checkUnnamed895(core.List<api.ExperimentVariations> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkExperimentVariations(o[0]);
  checkExperimentVariations(o[1]);
}

core.int buildCounterExperiment = 0;
buildExperiment() {
  var o = new api.Experiment();
  buildCounterExperiment++;
  if (buildCounterExperiment < 3) {
    o.accountId = "foo";
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.description = "foo";
    o.editableInGaUi = true;
    o.endTime = core.DateTime.parse("2002-02-27T14:01:02");
    o.equalWeighting = true;
    o.id = "foo";
    o.internalWebPropertyId = "foo";
    o.kind = "foo";
    o.minimumExperimentLengthInDays = 42;
    o.name = "foo";
    o.objectiveMetric = "foo";
    o.optimizationType = "foo";
    o.parentLink = buildExperimentParentLink();
    o.profileId = "foo";
    o.reasonExperimentEnded = "foo";
    o.rewriteVariationUrlsAsOriginal = true;
    o.selfLink = "foo";
    o.servingFramework = "foo";
    o.snippet = "foo";
    o.startTime = core.DateTime.parse("2002-02-27T14:01:02");
    o.status = "foo";
    o.trafficCoverage = 42.0;
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
    o.variations = buildUnnamed895();
    o.webPropertyId = "foo";
    o.winnerConfidenceLevel = 42.0;
    o.winnerFound = true;
  }
  buildCounterExperiment--;
  return o;
}

checkExperiment(api.Experiment o) {
  buildCounterExperiment++;
  if (buildCounterExperiment < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.description, unittest.equals('foo'));
    unittest.expect(o.editableInGaUi, unittest.isTrue);
    unittest.expect(o.endTime, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.equalWeighting, unittest.isTrue);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.internalWebPropertyId, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.minimumExperimentLengthInDays, unittest.equals(42));
    unittest.expect(o.name, unittest.equals('foo'));
    unittest.expect(o.objectiveMetric, unittest.equals('foo'));
    unittest.expect(o.optimizationType, unittest.equals('foo'));
    checkExperimentParentLink(o.parentLink);
    unittest.expect(o.profileId, unittest.equals('foo'));
    unittest.expect(o.reasonExperimentEnded, unittest.equals('foo'));
    unittest.expect(o.rewriteVariationUrlsAsOriginal, unittest.isTrue);
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.servingFramework, unittest.equals('foo'));
    unittest.expect(o.snippet, unittest.equals('foo'));
    unittest.expect(o.startTime, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.status, unittest.equals('foo'));
    unittest.expect(o.trafficCoverage, unittest.equals(42.0));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    checkUnnamed895(o.variations);
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
    unittest.expect(o.winnerConfidenceLevel, unittest.equals(42.0));
    unittest.expect(o.winnerFound, unittest.isTrue);
  }
  buildCounterExperiment--;
}

buildUnnamed896() {
  var o = new core.List<api.Experiment>();
  o.add(buildExperiment());
  o.add(buildExperiment());
  return o;
}

checkUnnamed896(core.List<api.Experiment> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkExperiment(o[0]);
  checkExperiment(o[1]);
}

core.int buildCounterExperiments = 0;
buildExperiments() {
  var o = new api.Experiments();
  buildCounterExperiments++;
  if (buildCounterExperiments < 3) {
    o.items = buildUnnamed896();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterExperiments--;
  return o;
}

checkExperiments(api.Experiments o) {
  buildCounterExperiments++;
  if (buildCounterExperiments < 3) {
    checkUnnamed896(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterExperiments--;
}

core.int buildCounterFilterAdvancedDetails = 0;
buildFilterAdvancedDetails() {
  var o = new api.FilterAdvancedDetails();
  buildCounterFilterAdvancedDetails++;
  if (buildCounterFilterAdvancedDetails < 3) {
    o.caseSensitive = true;
    o.extractA = "foo";
    o.extractB = "foo";
    o.fieldA = "foo";
    o.fieldAIndex = 42;
    o.fieldARequired = true;
    o.fieldB = "foo";
    o.fieldBIndex = 42;
    o.fieldBRequired = true;
    o.outputConstructor = "foo";
    o.outputToField = "foo";
    o.outputToFieldIndex = 42;
    o.overrideOutputField = true;
  }
  buildCounterFilterAdvancedDetails--;
  return o;
}

checkFilterAdvancedDetails(api.FilterAdvancedDetails o) {
  buildCounterFilterAdvancedDetails++;
  if (buildCounterFilterAdvancedDetails < 3) {
    unittest.expect(o.caseSensitive, unittest.isTrue);
    unittest.expect(o.extractA, unittest.equals('foo'));
    unittest.expect(o.extractB, unittest.equals('foo'));
    unittest.expect(o.fieldA, unittest.equals('foo'));
    unittest.expect(o.fieldAIndex, unittest.equals(42));
    unittest.expect(o.fieldARequired, unittest.isTrue);
    unittest.expect(o.fieldB, unittest.equals('foo'));
    unittest.expect(o.fieldBIndex, unittest.equals(42));
    unittest.expect(o.fieldBRequired, unittest.isTrue);
    unittest.expect(o.outputConstructor, unittest.equals('foo'));
    unittest.expect(o.outputToField, unittest.equals('foo'));
    unittest.expect(o.outputToFieldIndex, unittest.equals(42));
    unittest.expect(o.overrideOutputField, unittest.isTrue);
  }
  buildCounterFilterAdvancedDetails--;
}

core.int buildCounterFilterLowercaseDetails = 0;
buildFilterLowercaseDetails() {
  var o = new api.FilterLowercaseDetails();
  buildCounterFilterLowercaseDetails++;
  if (buildCounterFilterLowercaseDetails < 3) {
    o.field = "foo";
    o.fieldIndex = 42;
  }
  buildCounterFilterLowercaseDetails--;
  return o;
}

checkFilterLowercaseDetails(api.FilterLowercaseDetails o) {
  buildCounterFilterLowercaseDetails++;
  if (buildCounterFilterLowercaseDetails < 3) {
    unittest.expect(o.field, unittest.equals('foo'));
    unittest.expect(o.fieldIndex, unittest.equals(42));
  }
  buildCounterFilterLowercaseDetails--;
}

core.int buildCounterFilterParentLink = 0;
buildFilterParentLink() {
  var o = new api.FilterParentLink();
  buildCounterFilterParentLink++;
  if (buildCounterFilterParentLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterFilterParentLink--;
  return o;
}

checkFilterParentLink(api.FilterParentLink o) {
  buildCounterFilterParentLink++;
  if (buildCounterFilterParentLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterFilterParentLink--;
}

core.int buildCounterFilterSearchAndReplaceDetails = 0;
buildFilterSearchAndReplaceDetails() {
  var o = new api.FilterSearchAndReplaceDetails();
  buildCounterFilterSearchAndReplaceDetails++;
  if (buildCounterFilterSearchAndReplaceDetails < 3) {
    o.caseSensitive = true;
    o.field = "foo";
    o.fieldIndex = 42;
    o.replaceString = "foo";
    o.searchString = "foo";
  }
  buildCounterFilterSearchAndReplaceDetails--;
  return o;
}

checkFilterSearchAndReplaceDetails(api.FilterSearchAndReplaceDetails o) {
  buildCounterFilterSearchAndReplaceDetails++;
  if (buildCounterFilterSearchAndReplaceDetails < 3) {
    unittest.expect(o.caseSensitive, unittest.isTrue);
    unittest.expect(o.field, unittest.equals('foo'));
    unittest.expect(o.fieldIndex, unittest.equals(42));
    unittest.expect(o.replaceString, unittest.equals('foo'));
    unittest.expect(o.searchString, unittest.equals('foo'));
  }
  buildCounterFilterSearchAndReplaceDetails--;
}

core.int buildCounterFilterUppercaseDetails = 0;
buildFilterUppercaseDetails() {
  var o = new api.FilterUppercaseDetails();
  buildCounterFilterUppercaseDetails++;
  if (buildCounterFilterUppercaseDetails < 3) {
    o.field = "foo";
    o.fieldIndex = 42;
  }
  buildCounterFilterUppercaseDetails--;
  return o;
}

checkFilterUppercaseDetails(api.FilterUppercaseDetails o) {
  buildCounterFilterUppercaseDetails++;
  if (buildCounterFilterUppercaseDetails < 3) {
    unittest.expect(o.field, unittest.equals('foo'));
    unittest.expect(o.fieldIndex, unittest.equals(42));
  }
  buildCounterFilterUppercaseDetails--;
}

core.int buildCounterFilter = 0;
buildFilter() {
  var o = new api.Filter();
  buildCounterFilter++;
  if (buildCounterFilter < 3) {
    o.accountId = "foo";
    o.advancedDetails = buildFilterAdvancedDetails();
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.excludeDetails = buildFilterExpression();
    o.id = "foo";
    o.includeDetails = buildFilterExpression();
    o.kind = "foo";
    o.lowercaseDetails = buildFilterLowercaseDetails();
    o.name = "foo";
    o.parentLink = buildFilterParentLink();
    o.searchAndReplaceDetails = buildFilterSearchAndReplaceDetails();
    o.selfLink = "foo";
    o.type = "foo";
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
    o.uppercaseDetails = buildFilterUppercaseDetails();
  }
  buildCounterFilter--;
  return o;
}

checkFilter(api.Filter o) {
  buildCounterFilter++;
  if (buildCounterFilter < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    checkFilterAdvancedDetails(o.advancedDetails);
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    checkFilterExpression(o.excludeDetails);
    unittest.expect(o.id, unittest.equals('foo'));
    checkFilterExpression(o.includeDetails);
    unittest.expect(o.kind, unittest.equals('foo'));
    checkFilterLowercaseDetails(o.lowercaseDetails);
    unittest.expect(o.name, unittest.equals('foo'));
    checkFilterParentLink(o.parentLink);
    checkFilterSearchAndReplaceDetails(o.searchAndReplaceDetails);
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    checkFilterUppercaseDetails(o.uppercaseDetails);
  }
  buildCounterFilter--;
}

core.int buildCounterFilterExpression = 0;
buildFilterExpression() {
  var o = new api.FilterExpression();
  buildCounterFilterExpression++;
  if (buildCounterFilterExpression < 3) {
    o.caseSensitive = true;
    o.expressionValue = "foo";
    o.field = "foo";
    o.fieldIndex = 42;
    o.kind = "foo";
    o.matchType = "foo";
  }
  buildCounterFilterExpression--;
  return o;
}

checkFilterExpression(api.FilterExpression o) {
  buildCounterFilterExpression++;
  if (buildCounterFilterExpression < 3) {
    unittest.expect(o.caseSensitive, unittest.isTrue);
    unittest.expect(o.expressionValue, unittest.equals('foo'));
    unittest.expect(o.field, unittest.equals('foo'));
    unittest.expect(o.fieldIndex, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.matchType, unittest.equals('foo'));
  }
  buildCounterFilterExpression--;
}

core.int buildCounterFilterRef = 0;
buildFilterRef() {
  var o = new api.FilterRef();
  buildCounterFilterRef++;
  if (buildCounterFilterRef < 3) {
    o.accountId = "foo";
    o.href = "foo";
    o.id = "foo";
    o.kind = "foo";
    o.name = "foo";
  }
  buildCounterFilterRef--;
  return o;
}

checkFilterRef(api.FilterRef o) {
  buildCounterFilterRef++;
  if (buildCounterFilterRef < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
  }
  buildCounterFilterRef--;
}

buildUnnamed897() {
  var o = new core.List<api.Filter>();
  o.add(buildFilter());
  o.add(buildFilter());
  return o;
}

checkUnnamed897(core.List<api.Filter> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkFilter(o[0]);
  checkFilter(o[1]);
}

core.int buildCounterFilters = 0;
buildFilters() {
  var o = new api.Filters();
  buildCounterFilters++;
  if (buildCounterFilters < 3) {
    o.items = buildUnnamed897();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterFilters--;
  return o;
}

checkFilters(api.Filters o) {
  buildCounterFilters++;
  if (buildCounterFilters < 3) {
    checkUnnamed897(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterFilters--;
}

core.int buildCounterGaDataColumnHeaders = 0;
buildGaDataColumnHeaders() {
  var o = new api.GaDataColumnHeaders();
  buildCounterGaDataColumnHeaders++;
  if (buildCounterGaDataColumnHeaders < 3) {
    o.columnType = "foo";
    o.dataType = "foo";
    o.name = "foo";
  }
  buildCounterGaDataColumnHeaders--;
  return o;
}

checkGaDataColumnHeaders(api.GaDataColumnHeaders o) {
  buildCounterGaDataColumnHeaders++;
  if (buildCounterGaDataColumnHeaders < 3) {
    unittest.expect(o.columnType, unittest.equals('foo'));
    unittest.expect(o.dataType, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
  }
  buildCounterGaDataColumnHeaders--;
}

buildUnnamed898() {
  var o = new core.List<api.GaDataColumnHeaders>();
  o.add(buildGaDataColumnHeaders());
  o.add(buildGaDataColumnHeaders());
  return o;
}

checkUnnamed898(core.List<api.GaDataColumnHeaders> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkGaDataColumnHeaders(o[0]);
  checkGaDataColumnHeaders(o[1]);
}

core.int buildCounterGaDataDataTableCols = 0;
buildGaDataDataTableCols() {
  var o = new api.GaDataDataTableCols();
  buildCounterGaDataDataTableCols++;
  if (buildCounterGaDataDataTableCols < 3) {
    o.id = "foo";
    o.label = "foo";
    o.type = "foo";
  }
  buildCounterGaDataDataTableCols--;
  return o;
}

checkGaDataDataTableCols(api.GaDataDataTableCols o) {
  buildCounterGaDataDataTableCols++;
  if (buildCounterGaDataDataTableCols < 3) {
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.label, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterGaDataDataTableCols--;
}

buildUnnamed899() {
  var o = new core.List<api.GaDataDataTableCols>();
  o.add(buildGaDataDataTableCols());
  o.add(buildGaDataDataTableCols());
  return o;
}

checkUnnamed899(core.List<api.GaDataDataTableCols> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkGaDataDataTableCols(o[0]);
  checkGaDataDataTableCols(o[1]);
}

core.int buildCounterGaDataDataTableRowsC = 0;
buildGaDataDataTableRowsC() {
  var o = new api.GaDataDataTableRowsC();
  buildCounterGaDataDataTableRowsC++;
  if (buildCounterGaDataDataTableRowsC < 3) {
    o.v = "foo";
  }
  buildCounterGaDataDataTableRowsC--;
  return o;
}

checkGaDataDataTableRowsC(api.GaDataDataTableRowsC o) {
  buildCounterGaDataDataTableRowsC++;
  if (buildCounterGaDataDataTableRowsC < 3) {
    unittest.expect(o.v, unittest.equals('foo'));
  }
  buildCounterGaDataDataTableRowsC--;
}

buildUnnamed900() {
  var o = new core.List<api.GaDataDataTableRowsC>();
  o.add(buildGaDataDataTableRowsC());
  o.add(buildGaDataDataTableRowsC());
  return o;
}

checkUnnamed900(core.List<api.GaDataDataTableRowsC> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkGaDataDataTableRowsC(o[0]);
  checkGaDataDataTableRowsC(o[1]);
}

core.int buildCounterGaDataDataTableRows = 0;
buildGaDataDataTableRows() {
  var o = new api.GaDataDataTableRows();
  buildCounterGaDataDataTableRows++;
  if (buildCounterGaDataDataTableRows < 3) {
    o.c = buildUnnamed900();
  }
  buildCounterGaDataDataTableRows--;
  return o;
}

checkGaDataDataTableRows(api.GaDataDataTableRows o) {
  buildCounterGaDataDataTableRows++;
  if (buildCounterGaDataDataTableRows < 3) {
    checkUnnamed900(o.c);
  }
  buildCounterGaDataDataTableRows--;
}

buildUnnamed901() {
  var o = new core.List<api.GaDataDataTableRows>();
  o.add(buildGaDataDataTableRows());
  o.add(buildGaDataDataTableRows());
  return o;
}

checkUnnamed901(core.List<api.GaDataDataTableRows> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkGaDataDataTableRows(o[0]);
  checkGaDataDataTableRows(o[1]);
}

core.int buildCounterGaDataDataTable = 0;
buildGaDataDataTable() {
  var o = new api.GaDataDataTable();
  buildCounterGaDataDataTable++;
  if (buildCounterGaDataDataTable < 3) {
    o.cols = buildUnnamed899();
    o.rows = buildUnnamed901();
  }
  buildCounterGaDataDataTable--;
  return o;
}

checkGaDataDataTable(api.GaDataDataTable o) {
  buildCounterGaDataDataTable++;
  if (buildCounterGaDataDataTable < 3) {
    checkUnnamed899(o.cols);
    checkUnnamed901(o.rows);
  }
  buildCounterGaDataDataTable--;
}

core.int buildCounterGaDataProfileInfo = 0;
buildGaDataProfileInfo() {
  var o = new api.GaDataProfileInfo();
  buildCounterGaDataProfileInfo++;
  if (buildCounterGaDataProfileInfo < 3) {
    o.accountId = "foo";
    o.internalWebPropertyId = "foo";
    o.profileId = "foo";
    o.profileName = "foo";
    o.tableId = "foo";
    o.webPropertyId = "foo";
  }
  buildCounterGaDataProfileInfo--;
  return o;
}

checkGaDataProfileInfo(api.GaDataProfileInfo o) {
  buildCounterGaDataProfileInfo++;
  if (buildCounterGaDataProfileInfo < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.internalWebPropertyId, unittest.equals('foo'));
    unittest.expect(o.profileId, unittest.equals('foo'));
    unittest.expect(o.profileName, unittest.equals('foo'));
    unittest.expect(o.tableId, unittest.equals('foo'));
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
  }
  buildCounterGaDataProfileInfo--;
}

buildUnnamed902() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed902(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

buildUnnamed903() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed903(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterGaDataQuery = 0;
buildGaDataQuery() {
  var o = new api.GaDataQuery();
  buildCounterGaDataQuery++;
  if (buildCounterGaDataQuery < 3) {
    o.dimensions = "foo";
    o.end_date = "foo";
    o.filters = "foo";
    o.ids = "foo";
    o.max_results = 42;
    o.metrics = buildUnnamed902();
    o.samplingLevel = "foo";
    o.segment = "foo";
    o.sort = buildUnnamed903();
    o.start_date = "foo";
    o.start_index = 42;
  }
  buildCounterGaDataQuery--;
  return o;
}

checkGaDataQuery(api.GaDataQuery o) {
  buildCounterGaDataQuery++;
  if (buildCounterGaDataQuery < 3) {
    unittest.expect(o.dimensions, unittest.equals('foo'));
    unittest.expect(o.end_date, unittest.equals('foo'));
    unittest.expect(o.filters, unittest.equals('foo'));
    unittest.expect(o.ids, unittest.equals('foo'));
    unittest.expect(o.max_results, unittest.equals(42));
    checkUnnamed902(o.metrics);
    unittest.expect(o.samplingLevel, unittest.equals('foo'));
    unittest.expect(o.segment, unittest.equals('foo'));
    checkUnnamed903(o.sort);
    unittest.expect(o.start_date, unittest.equals('foo'));
    unittest.expect(o.start_index, unittest.equals(42));
  }
  buildCounterGaDataQuery--;
}

buildUnnamed904() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed904(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

buildUnnamed905() {
  var o = new core.List<core.List<core.String>>();
  o.add(buildUnnamed904());
  o.add(buildUnnamed904());
  return o;
}

checkUnnamed905(core.List<core.List<core.String>> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkUnnamed904(o[0]);
  checkUnnamed904(o[1]);
}

buildUnnamed906() {
  var o = new core.Map<core.String, core.String>();
  o["x"] = "foo";
  o["y"] = "foo";
  return o;
}

checkUnnamed906(core.Map<core.String, core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o["x"], unittest.equals('foo'));
  unittest.expect(o["y"], unittest.equals('foo'));
}

core.int buildCounterGaData = 0;
buildGaData() {
  var o = new api.GaData();
  buildCounterGaData++;
  if (buildCounterGaData < 3) {
    o.columnHeaders = buildUnnamed898();
    o.containsSampledData = true;
    o.dataTable = buildGaDataDataTable();
    o.id = "foo";
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.profileInfo = buildGaDataProfileInfo();
    o.query = buildGaDataQuery();
    o.rows = buildUnnamed905();
    o.sampleSize = "foo";
    o.sampleSpace = "foo";
    o.selfLink = "foo";
    o.totalResults = 42;
    o.totalsForAllResults = buildUnnamed906();
  }
  buildCounterGaData--;
  return o;
}

checkGaData(api.GaData o) {
  buildCounterGaData++;
  if (buildCounterGaData < 3) {
    checkUnnamed898(o.columnHeaders);
    unittest.expect(o.containsSampledData, unittest.isTrue);
    checkGaDataDataTable(o.dataTable);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    checkGaDataProfileInfo(o.profileInfo);
    checkGaDataQuery(o.query);
    checkUnnamed905(o.rows);
    unittest.expect(o.sampleSize, unittest.equals('foo'));
    unittest.expect(o.sampleSpace, unittest.equals('foo'));
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.totalResults, unittest.equals(42));
    checkUnnamed906(o.totalsForAllResults);
  }
  buildCounterGaData--;
}

core.int buildCounterGoalEventDetailsEventConditions = 0;
buildGoalEventDetailsEventConditions() {
  var o = new api.GoalEventDetailsEventConditions();
  buildCounterGoalEventDetailsEventConditions++;
  if (buildCounterGoalEventDetailsEventConditions < 3) {
    o.comparisonType = "foo";
    o.comparisonValue = "foo";
    o.expression = "foo";
    o.matchType = "foo";
    o.type = "foo";
  }
  buildCounterGoalEventDetailsEventConditions--;
  return o;
}

checkGoalEventDetailsEventConditions(api.GoalEventDetailsEventConditions o) {
  buildCounterGoalEventDetailsEventConditions++;
  if (buildCounterGoalEventDetailsEventConditions < 3) {
    unittest.expect(o.comparisonType, unittest.equals('foo'));
    unittest.expect(o.comparisonValue, unittest.equals('foo'));
    unittest.expect(o.expression, unittest.equals('foo'));
    unittest.expect(o.matchType, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterGoalEventDetailsEventConditions--;
}

buildUnnamed907() {
  var o = new core.List<api.GoalEventDetailsEventConditions>();
  o.add(buildGoalEventDetailsEventConditions());
  o.add(buildGoalEventDetailsEventConditions());
  return o;
}

checkUnnamed907(core.List<api.GoalEventDetailsEventConditions> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkGoalEventDetailsEventConditions(o[0]);
  checkGoalEventDetailsEventConditions(o[1]);
}

core.int buildCounterGoalEventDetails = 0;
buildGoalEventDetails() {
  var o = new api.GoalEventDetails();
  buildCounterGoalEventDetails++;
  if (buildCounterGoalEventDetails < 3) {
    o.eventConditions = buildUnnamed907();
    o.useEventValue = true;
  }
  buildCounterGoalEventDetails--;
  return o;
}

checkGoalEventDetails(api.GoalEventDetails o) {
  buildCounterGoalEventDetails++;
  if (buildCounterGoalEventDetails < 3) {
    checkUnnamed907(o.eventConditions);
    unittest.expect(o.useEventValue, unittest.isTrue);
  }
  buildCounterGoalEventDetails--;
}

core.int buildCounterGoalParentLink = 0;
buildGoalParentLink() {
  var o = new api.GoalParentLink();
  buildCounterGoalParentLink++;
  if (buildCounterGoalParentLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterGoalParentLink--;
  return o;
}

checkGoalParentLink(api.GoalParentLink o) {
  buildCounterGoalParentLink++;
  if (buildCounterGoalParentLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterGoalParentLink--;
}

core.int buildCounterGoalUrlDestinationDetailsSteps = 0;
buildGoalUrlDestinationDetailsSteps() {
  var o = new api.GoalUrlDestinationDetailsSteps();
  buildCounterGoalUrlDestinationDetailsSteps++;
  if (buildCounterGoalUrlDestinationDetailsSteps < 3) {
    o.name = "foo";
    o.number = 42;
    o.url = "foo";
  }
  buildCounterGoalUrlDestinationDetailsSteps--;
  return o;
}

checkGoalUrlDestinationDetailsSteps(api.GoalUrlDestinationDetailsSteps o) {
  buildCounterGoalUrlDestinationDetailsSteps++;
  if (buildCounterGoalUrlDestinationDetailsSteps < 3) {
    unittest.expect(o.name, unittest.equals('foo'));
    unittest.expect(o.number, unittest.equals(42));
    unittest.expect(o.url, unittest.equals('foo'));
  }
  buildCounterGoalUrlDestinationDetailsSteps--;
}

buildUnnamed908() {
  var o = new core.List<api.GoalUrlDestinationDetailsSteps>();
  o.add(buildGoalUrlDestinationDetailsSteps());
  o.add(buildGoalUrlDestinationDetailsSteps());
  return o;
}

checkUnnamed908(core.List<api.GoalUrlDestinationDetailsSteps> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkGoalUrlDestinationDetailsSteps(o[0]);
  checkGoalUrlDestinationDetailsSteps(o[1]);
}

core.int buildCounterGoalUrlDestinationDetails = 0;
buildGoalUrlDestinationDetails() {
  var o = new api.GoalUrlDestinationDetails();
  buildCounterGoalUrlDestinationDetails++;
  if (buildCounterGoalUrlDestinationDetails < 3) {
    o.caseSensitive = true;
    o.firstStepRequired = true;
    o.matchType = "foo";
    o.steps = buildUnnamed908();
    o.url = "foo";
  }
  buildCounterGoalUrlDestinationDetails--;
  return o;
}

checkGoalUrlDestinationDetails(api.GoalUrlDestinationDetails o) {
  buildCounterGoalUrlDestinationDetails++;
  if (buildCounterGoalUrlDestinationDetails < 3) {
    unittest.expect(o.caseSensitive, unittest.isTrue);
    unittest.expect(o.firstStepRequired, unittest.isTrue);
    unittest.expect(o.matchType, unittest.equals('foo'));
    checkUnnamed908(o.steps);
    unittest.expect(o.url, unittest.equals('foo'));
  }
  buildCounterGoalUrlDestinationDetails--;
}

core.int buildCounterGoalVisitNumPagesDetails = 0;
buildGoalVisitNumPagesDetails() {
  var o = new api.GoalVisitNumPagesDetails();
  buildCounterGoalVisitNumPagesDetails++;
  if (buildCounterGoalVisitNumPagesDetails < 3) {
    o.comparisonType = "foo";
    o.comparisonValue = "foo";
  }
  buildCounterGoalVisitNumPagesDetails--;
  return o;
}

checkGoalVisitNumPagesDetails(api.GoalVisitNumPagesDetails o) {
  buildCounterGoalVisitNumPagesDetails++;
  if (buildCounterGoalVisitNumPagesDetails < 3) {
    unittest.expect(o.comparisonType, unittest.equals('foo'));
    unittest.expect(o.comparisonValue, unittest.equals('foo'));
  }
  buildCounterGoalVisitNumPagesDetails--;
}

core.int buildCounterGoalVisitTimeOnSiteDetails = 0;
buildGoalVisitTimeOnSiteDetails() {
  var o = new api.GoalVisitTimeOnSiteDetails();
  buildCounterGoalVisitTimeOnSiteDetails++;
  if (buildCounterGoalVisitTimeOnSiteDetails < 3) {
    o.comparisonType = "foo";
    o.comparisonValue = "foo";
  }
  buildCounterGoalVisitTimeOnSiteDetails--;
  return o;
}

checkGoalVisitTimeOnSiteDetails(api.GoalVisitTimeOnSiteDetails o) {
  buildCounterGoalVisitTimeOnSiteDetails++;
  if (buildCounterGoalVisitTimeOnSiteDetails < 3) {
    unittest.expect(o.comparisonType, unittest.equals('foo'));
    unittest.expect(o.comparisonValue, unittest.equals('foo'));
  }
  buildCounterGoalVisitTimeOnSiteDetails--;
}

core.int buildCounterGoal = 0;
buildGoal() {
  var o = new api.Goal();
  buildCounterGoal++;
  if (buildCounterGoal < 3) {
    o.accountId = "foo";
    o.active = true;
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.eventDetails = buildGoalEventDetails();
    o.id = "foo";
    o.internalWebPropertyId = "foo";
    o.kind = "foo";
    o.name = "foo";
    o.parentLink = buildGoalParentLink();
    o.profileId = "foo";
    o.selfLink = "foo";
    o.type = "foo";
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
    o.urlDestinationDetails = buildGoalUrlDestinationDetails();
    o.value = 42.0;
    o.visitNumPagesDetails = buildGoalVisitNumPagesDetails();
    o.visitTimeOnSiteDetails = buildGoalVisitTimeOnSiteDetails();
    o.webPropertyId = "foo";
  }
  buildCounterGoal--;
  return o;
}

checkGoal(api.Goal o) {
  buildCounterGoal++;
  if (buildCounterGoal < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.active, unittest.isTrue);
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    checkGoalEventDetails(o.eventDetails);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.internalWebPropertyId, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    checkGoalParentLink(o.parentLink);
    unittest.expect(o.profileId, unittest.equals('foo'));
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    checkGoalUrlDestinationDetails(o.urlDestinationDetails);
    unittest.expect(o.value, unittest.equals(42.0));
    checkGoalVisitNumPagesDetails(o.visitNumPagesDetails);
    checkGoalVisitTimeOnSiteDetails(o.visitTimeOnSiteDetails);
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
  }
  buildCounterGoal--;
}

buildUnnamed909() {
  var o = new core.List<api.Goal>();
  o.add(buildGoal());
  o.add(buildGoal());
  return o;
}

checkUnnamed909(core.List<api.Goal> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkGoal(o[0]);
  checkGoal(o[1]);
}

core.int buildCounterGoals = 0;
buildGoals() {
  var o = new api.Goals();
  buildCounterGoals++;
  if (buildCounterGoals < 3) {
    o.items = buildUnnamed909();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterGoals--;
  return o;
}

checkGoals(api.Goals o) {
  buildCounterGoals++;
  if (buildCounterGoals < 3) {
    checkUnnamed909(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterGoals--;
}

core.int buildCounterMcfDataColumnHeaders = 0;
buildMcfDataColumnHeaders() {
  var o = new api.McfDataColumnHeaders();
  buildCounterMcfDataColumnHeaders++;
  if (buildCounterMcfDataColumnHeaders < 3) {
    o.columnType = "foo";
    o.dataType = "foo";
    o.name = "foo";
  }
  buildCounterMcfDataColumnHeaders--;
  return o;
}

checkMcfDataColumnHeaders(api.McfDataColumnHeaders o) {
  buildCounterMcfDataColumnHeaders++;
  if (buildCounterMcfDataColumnHeaders < 3) {
    unittest.expect(o.columnType, unittest.equals('foo'));
    unittest.expect(o.dataType, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
  }
  buildCounterMcfDataColumnHeaders--;
}

buildUnnamed910() {
  var o = new core.List<api.McfDataColumnHeaders>();
  o.add(buildMcfDataColumnHeaders());
  o.add(buildMcfDataColumnHeaders());
  return o;
}

checkUnnamed910(core.List<api.McfDataColumnHeaders> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkMcfDataColumnHeaders(o[0]);
  checkMcfDataColumnHeaders(o[1]);
}

core.int buildCounterMcfDataProfileInfo = 0;
buildMcfDataProfileInfo() {
  var o = new api.McfDataProfileInfo();
  buildCounterMcfDataProfileInfo++;
  if (buildCounterMcfDataProfileInfo < 3) {
    o.accountId = "foo";
    o.internalWebPropertyId = "foo";
    o.profileId = "foo";
    o.profileName = "foo";
    o.tableId = "foo";
    o.webPropertyId = "foo";
  }
  buildCounterMcfDataProfileInfo--;
  return o;
}

checkMcfDataProfileInfo(api.McfDataProfileInfo o) {
  buildCounterMcfDataProfileInfo++;
  if (buildCounterMcfDataProfileInfo < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.internalWebPropertyId, unittest.equals('foo'));
    unittest.expect(o.profileId, unittest.equals('foo'));
    unittest.expect(o.profileName, unittest.equals('foo'));
    unittest.expect(o.tableId, unittest.equals('foo'));
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
  }
  buildCounterMcfDataProfileInfo--;
}

buildUnnamed911() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed911(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

buildUnnamed912() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed912(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterMcfDataQuery = 0;
buildMcfDataQuery() {
  var o = new api.McfDataQuery();
  buildCounterMcfDataQuery++;
  if (buildCounterMcfDataQuery < 3) {
    o.dimensions = "foo";
    o.end_date = "foo";
    o.filters = "foo";
    o.ids = "foo";
    o.max_results = 42;
    o.metrics = buildUnnamed911();
    o.samplingLevel = "foo";
    o.segment = "foo";
    o.sort = buildUnnamed912();
    o.start_date = "foo";
    o.start_index = 42;
  }
  buildCounterMcfDataQuery--;
  return o;
}

checkMcfDataQuery(api.McfDataQuery o) {
  buildCounterMcfDataQuery++;
  if (buildCounterMcfDataQuery < 3) {
    unittest.expect(o.dimensions, unittest.equals('foo'));
    unittest.expect(o.end_date, unittest.equals('foo'));
    unittest.expect(o.filters, unittest.equals('foo'));
    unittest.expect(o.ids, unittest.equals('foo'));
    unittest.expect(o.max_results, unittest.equals(42));
    checkUnnamed911(o.metrics);
    unittest.expect(o.samplingLevel, unittest.equals('foo'));
    unittest.expect(o.segment, unittest.equals('foo'));
    checkUnnamed912(o.sort);
    unittest.expect(o.start_date, unittest.equals('foo'));
    unittest.expect(o.start_index, unittest.equals(42));
  }
  buildCounterMcfDataQuery--;
}

core.int buildCounterMcfDataRowsConversionPathValue = 0;
buildMcfDataRowsConversionPathValue() {
  var o = new api.McfDataRowsConversionPathValue();
  buildCounterMcfDataRowsConversionPathValue++;
  if (buildCounterMcfDataRowsConversionPathValue < 3) {
    o.interactionType = "foo";
    o.nodeValue = "foo";
  }
  buildCounterMcfDataRowsConversionPathValue--;
  return o;
}

checkMcfDataRowsConversionPathValue(api.McfDataRowsConversionPathValue o) {
  buildCounterMcfDataRowsConversionPathValue++;
  if (buildCounterMcfDataRowsConversionPathValue < 3) {
    unittest.expect(o.interactionType, unittest.equals('foo'));
    unittest.expect(o.nodeValue, unittest.equals('foo'));
  }
  buildCounterMcfDataRowsConversionPathValue--;
}

buildUnnamed913() {
  var o = new core.List<api.McfDataRowsConversionPathValue>();
  o.add(buildMcfDataRowsConversionPathValue());
  o.add(buildMcfDataRowsConversionPathValue());
  return o;
}

checkUnnamed913(core.List<api.McfDataRowsConversionPathValue> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkMcfDataRowsConversionPathValue(o[0]);
  checkMcfDataRowsConversionPathValue(o[1]);
}

core.int buildCounterMcfDataRows = 0;
buildMcfDataRows() {
  var o = new api.McfDataRows();
  buildCounterMcfDataRows++;
  if (buildCounterMcfDataRows < 3) {
    o.conversionPathValue = buildUnnamed913();
    o.primitiveValue = "foo";
  }
  buildCounterMcfDataRows--;
  return o;
}

checkMcfDataRows(api.McfDataRows o) {
  buildCounterMcfDataRows++;
  if (buildCounterMcfDataRows < 3) {
    checkUnnamed913(o.conversionPathValue);
    unittest.expect(o.primitiveValue, unittest.equals('foo'));
  }
  buildCounterMcfDataRows--;
}

buildUnnamed914() {
  var o = new core.List<api.McfDataRows>();
  o.add(buildMcfDataRows());
  o.add(buildMcfDataRows());
  return o;
}

checkUnnamed914(core.List<api.McfDataRows> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkMcfDataRows(o[0]);
  checkMcfDataRows(o[1]);
}

buildUnnamed915() {
  var o = new core.List<core.List<api.McfDataRows>>();
  o.add(buildUnnamed914());
  o.add(buildUnnamed914());
  return o;
}

checkUnnamed915(core.List<core.List<api.McfDataRows>> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkUnnamed914(o[0]);
  checkUnnamed914(o[1]);
}

buildUnnamed916() {
  var o = new core.Map<core.String, core.String>();
  o["x"] = "foo";
  o["y"] = "foo";
  return o;
}

checkUnnamed916(core.Map<core.String, core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o["x"], unittest.equals('foo'));
  unittest.expect(o["y"], unittest.equals('foo'));
}

core.int buildCounterMcfData = 0;
buildMcfData() {
  var o = new api.McfData();
  buildCounterMcfData++;
  if (buildCounterMcfData < 3) {
    o.columnHeaders = buildUnnamed910();
    o.containsSampledData = true;
    o.id = "foo";
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.profileInfo = buildMcfDataProfileInfo();
    o.query = buildMcfDataQuery();
    o.rows = buildUnnamed915();
    o.sampleSize = "foo";
    o.sampleSpace = "foo";
    o.selfLink = "foo";
    o.totalResults = 42;
    o.totalsForAllResults = buildUnnamed916();
  }
  buildCounterMcfData--;
  return o;
}

checkMcfData(api.McfData o) {
  buildCounterMcfData++;
  if (buildCounterMcfData < 3) {
    checkUnnamed910(o.columnHeaders);
    unittest.expect(o.containsSampledData, unittest.isTrue);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    checkMcfDataProfileInfo(o.profileInfo);
    checkMcfDataQuery(o.query);
    checkUnnamed915(o.rows);
    unittest.expect(o.sampleSize, unittest.equals('foo'));
    unittest.expect(o.sampleSpace, unittest.equals('foo'));
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.totalResults, unittest.equals(42));
    checkUnnamed916(o.totalsForAllResults);
  }
  buildCounterMcfData--;
}

core.int buildCounterProfileChildLink = 0;
buildProfileChildLink() {
  var o = new api.ProfileChildLink();
  buildCounterProfileChildLink++;
  if (buildCounterProfileChildLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterProfileChildLink--;
  return o;
}

checkProfileChildLink(api.ProfileChildLink o) {
  buildCounterProfileChildLink++;
  if (buildCounterProfileChildLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterProfileChildLink--;
}

core.int buildCounterProfileParentLink = 0;
buildProfileParentLink() {
  var o = new api.ProfileParentLink();
  buildCounterProfileParentLink++;
  if (buildCounterProfileParentLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterProfileParentLink--;
  return o;
}

checkProfileParentLink(api.ProfileParentLink o) {
  buildCounterProfileParentLink++;
  if (buildCounterProfileParentLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterProfileParentLink--;
}

buildUnnamed917() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed917(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterProfilePermissions = 0;
buildProfilePermissions() {
  var o = new api.ProfilePermissions();
  buildCounterProfilePermissions++;
  if (buildCounterProfilePermissions < 3) {
    o.effective = buildUnnamed917();
  }
  buildCounterProfilePermissions--;
  return o;
}

checkProfilePermissions(api.ProfilePermissions o) {
  buildCounterProfilePermissions++;
  if (buildCounterProfilePermissions < 3) {
    checkUnnamed917(o.effective);
  }
  buildCounterProfilePermissions--;
}

core.int buildCounterProfile = 0;
buildProfile() {
  var o = new api.Profile();
  buildCounterProfile++;
  if (buildCounterProfile < 3) {
    o.accountId = "foo";
    o.childLink = buildProfileChildLink();
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.currency = "foo";
    o.defaultPage = "foo";
    o.eCommerceTracking = true;
    o.enhancedECommerceTracking = true;
    o.excludeQueryParameters = "foo";
    o.id = "foo";
    o.internalWebPropertyId = "foo";
    o.kind = "foo";
    o.name = "foo";
    o.parentLink = buildProfileParentLink();
    o.permissions = buildProfilePermissions();
    o.selfLink = "foo";
    o.siteSearchCategoryParameters = "foo";
    o.siteSearchQueryParameters = "foo";
    o.stripSiteSearchCategoryParameters = true;
    o.stripSiteSearchQueryParameters = true;
    o.timezone = "foo";
    o.type = "foo";
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
    o.webPropertyId = "foo";
    o.websiteUrl = "foo";
  }
  buildCounterProfile--;
  return o;
}

checkProfile(api.Profile o) {
  buildCounterProfile++;
  if (buildCounterProfile < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    checkProfileChildLink(o.childLink);
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.currency, unittest.equals('foo'));
    unittest.expect(o.defaultPage, unittest.equals('foo'));
    unittest.expect(o.eCommerceTracking, unittest.isTrue);
    unittest.expect(o.enhancedECommerceTracking, unittest.isTrue);
    unittest.expect(o.excludeQueryParameters, unittest.equals('foo'));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.internalWebPropertyId, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    checkProfileParentLink(o.parentLink);
    checkProfilePermissions(o.permissions);
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.siteSearchCategoryParameters, unittest.equals('foo'));
    unittest.expect(o.siteSearchQueryParameters, unittest.equals('foo'));
    unittest.expect(o.stripSiteSearchCategoryParameters, unittest.isTrue);
    unittest.expect(o.stripSiteSearchQueryParameters, unittest.isTrue);
    unittest.expect(o.timezone, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
    unittest.expect(o.websiteUrl, unittest.equals('foo'));
  }
  buildCounterProfile--;
}

core.int buildCounterProfileFilterLink = 0;
buildProfileFilterLink() {
  var o = new api.ProfileFilterLink();
  buildCounterProfileFilterLink++;
  if (buildCounterProfileFilterLink < 3) {
    o.filterRef = buildFilterRef();
    o.id = "foo";
    o.kind = "foo";
    o.profileRef = buildProfileRef();
    o.rank = 42;
    o.selfLink = "foo";
  }
  buildCounterProfileFilterLink--;
  return o;
}

checkProfileFilterLink(api.ProfileFilterLink o) {
  buildCounterProfileFilterLink++;
  if (buildCounterProfileFilterLink < 3) {
    checkFilterRef(o.filterRef);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    checkProfileRef(o.profileRef);
    unittest.expect(o.rank, unittest.equals(42));
    unittest.expect(o.selfLink, unittest.equals('foo'));
  }
  buildCounterProfileFilterLink--;
}

buildUnnamed918() {
  var o = new core.List<api.ProfileFilterLink>();
  o.add(buildProfileFilterLink());
  o.add(buildProfileFilterLink());
  return o;
}

checkUnnamed918(core.List<api.ProfileFilterLink> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkProfileFilterLink(o[0]);
  checkProfileFilterLink(o[1]);
}

core.int buildCounterProfileFilterLinks = 0;
buildProfileFilterLinks() {
  var o = new api.ProfileFilterLinks();
  buildCounterProfileFilterLinks++;
  if (buildCounterProfileFilterLinks < 3) {
    o.items = buildUnnamed918();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterProfileFilterLinks--;
  return o;
}

checkProfileFilterLinks(api.ProfileFilterLinks o) {
  buildCounterProfileFilterLinks++;
  if (buildCounterProfileFilterLinks < 3) {
    checkUnnamed918(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterProfileFilterLinks--;
}

core.int buildCounterProfileRef = 0;
buildProfileRef() {
  var o = new api.ProfileRef();
  buildCounterProfileRef++;
  if (buildCounterProfileRef < 3) {
    o.accountId = "foo";
    o.href = "foo";
    o.id = "foo";
    o.internalWebPropertyId = "foo";
    o.kind = "foo";
    o.name = "foo";
    o.webPropertyId = "foo";
  }
  buildCounterProfileRef--;
  return o;
}

checkProfileRef(api.ProfileRef o) {
  buildCounterProfileRef++;
  if (buildCounterProfileRef < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.internalWebPropertyId, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
  }
  buildCounterProfileRef--;
}

core.int buildCounterProfileSummary = 0;
buildProfileSummary() {
  var o = new api.ProfileSummary();
  buildCounterProfileSummary++;
  if (buildCounterProfileSummary < 3) {
    o.id = "foo";
    o.kind = "foo";
    o.name = "foo";
    o.type = "foo";
  }
  buildCounterProfileSummary--;
  return o;
}

checkProfileSummary(api.ProfileSummary o) {
  buildCounterProfileSummary++;
  if (buildCounterProfileSummary < 3) {
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterProfileSummary--;
}

buildUnnamed919() {
  var o = new core.List<api.Profile>();
  o.add(buildProfile());
  o.add(buildProfile());
  return o;
}

checkUnnamed919(core.List<api.Profile> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkProfile(o[0]);
  checkProfile(o[1]);
}

core.int buildCounterProfiles = 0;
buildProfiles() {
  var o = new api.Profiles();
  buildCounterProfiles++;
  if (buildCounterProfiles < 3) {
    o.items = buildUnnamed919();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterProfiles--;
  return o;
}

checkProfiles(api.Profiles o) {
  buildCounterProfiles++;
  if (buildCounterProfiles < 3) {
    checkUnnamed919(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterProfiles--;
}

core.int buildCounterRealtimeDataColumnHeaders = 0;
buildRealtimeDataColumnHeaders() {
  var o = new api.RealtimeDataColumnHeaders();
  buildCounterRealtimeDataColumnHeaders++;
  if (buildCounterRealtimeDataColumnHeaders < 3) {
    o.columnType = "foo";
    o.dataType = "foo";
    o.name = "foo";
  }
  buildCounterRealtimeDataColumnHeaders--;
  return o;
}

checkRealtimeDataColumnHeaders(api.RealtimeDataColumnHeaders o) {
  buildCounterRealtimeDataColumnHeaders++;
  if (buildCounterRealtimeDataColumnHeaders < 3) {
    unittest.expect(o.columnType, unittest.equals('foo'));
    unittest.expect(o.dataType, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
  }
  buildCounterRealtimeDataColumnHeaders--;
}

buildUnnamed920() {
  var o = new core.List<api.RealtimeDataColumnHeaders>();
  o.add(buildRealtimeDataColumnHeaders());
  o.add(buildRealtimeDataColumnHeaders());
  return o;
}

checkUnnamed920(core.List<api.RealtimeDataColumnHeaders> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkRealtimeDataColumnHeaders(o[0]);
  checkRealtimeDataColumnHeaders(o[1]);
}

core.int buildCounterRealtimeDataProfileInfo = 0;
buildRealtimeDataProfileInfo() {
  var o = new api.RealtimeDataProfileInfo();
  buildCounterRealtimeDataProfileInfo++;
  if (buildCounterRealtimeDataProfileInfo < 3) {
    o.accountId = "foo";
    o.internalWebPropertyId = "foo";
    o.profileId = "foo";
    o.profileName = "foo";
    o.tableId = "foo";
    o.webPropertyId = "foo";
  }
  buildCounterRealtimeDataProfileInfo--;
  return o;
}

checkRealtimeDataProfileInfo(api.RealtimeDataProfileInfo o) {
  buildCounterRealtimeDataProfileInfo++;
  if (buildCounterRealtimeDataProfileInfo < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.internalWebPropertyId, unittest.equals('foo'));
    unittest.expect(o.profileId, unittest.equals('foo'));
    unittest.expect(o.profileName, unittest.equals('foo'));
    unittest.expect(o.tableId, unittest.equals('foo'));
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
  }
  buildCounterRealtimeDataProfileInfo--;
}

buildUnnamed921() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed921(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

buildUnnamed922() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed922(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterRealtimeDataQuery = 0;
buildRealtimeDataQuery() {
  var o = new api.RealtimeDataQuery();
  buildCounterRealtimeDataQuery++;
  if (buildCounterRealtimeDataQuery < 3) {
    o.dimensions = "foo";
    o.filters = "foo";
    o.ids = "foo";
    o.max_results = 42;
    o.metrics = buildUnnamed921();
    o.sort = buildUnnamed922();
  }
  buildCounterRealtimeDataQuery--;
  return o;
}

checkRealtimeDataQuery(api.RealtimeDataQuery o) {
  buildCounterRealtimeDataQuery++;
  if (buildCounterRealtimeDataQuery < 3) {
    unittest.expect(o.dimensions, unittest.equals('foo'));
    unittest.expect(o.filters, unittest.equals('foo'));
    unittest.expect(o.ids, unittest.equals('foo'));
    unittest.expect(o.max_results, unittest.equals(42));
    checkUnnamed921(o.metrics);
    checkUnnamed922(o.sort);
  }
  buildCounterRealtimeDataQuery--;
}

buildUnnamed923() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed923(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

buildUnnamed924() {
  var o = new core.List<core.List<core.String>>();
  o.add(buildUnnamed923());
  o.add(buildUnnamed923());
  return o;
}

checkUnnamed924(core.List<core.List<core.String>> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkUnnamed923(o[0]);
  checkUnnamed923(o[1]);
}

buildUnnamed925() {
  var o = new core.Map<core.String, core.String>();
  o["x"] = "foo";
  o["y"] = "foo";
  return o;
}

checkUnnamed925(core.Map<core.String, core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o["x"], unittest.equals('foo'));
  unittest.expect(o["y"], unittest.equals('foo'));
}

core.int buildCounterRealtimeData = 0;
buildRealtimeData() {
  var o = new api.RealtimeData();
  buildCounterRealtimeData++;
  if (buildCounterRealtimeData < 3) {
    o.columnHeaders = buildUnnamed920();
    o.id = "foo";
    o.kind = "foo";
    o.profileInfo = buildRealtimeDataProfileInfo();
    o.query = buildRealtimeDataQuery();
    o.rows = buildUnnamed924();
    o.selfLink = "foo";
    o.totalResults = 42;
    o.totalsForAllResults = buildUnnamed925();
  }
  buildCounterRealtimeData--;
  return o;
}

checkRealtimeData(api.RealtimeData o) {
  buildCounterRealtimeData++;
  if (buildCounterRealtimeData < 3) {
    checkUnnamed920(o.columnHeaders);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    checkRealtimeDataProfileInfo(o.profileInfo);
    checkRealtimeDataQuery(o.query);
    checkUnnamed924(o.rows);
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.totalResults, unittest.equals(42));
    checkUnnamed925(o.totalsForAllResults);
  }
  buildCounterRealtimeData--;
}

core.int buildCounterSegment = 0;
buildSegment() {
  var o = new api.Segment();
  buildCounterSegment++;
  if (buildCounterSegment < 3) {
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.definition = "foo";
    o.id = "foo";
    o.kind = "foo";
    o.name = "foo";
    o.segmentId = "foo";
    o.selfLink = "foo";
    o.type = "foo";
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
  }
  buildCounterSegment--;
  return o;
}

checkSegment(api.Segment o) {
  buildCounterSegment++;
  if (buildCounterSegment < 3) {
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.definition, unittest.equals('foo'));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    unittest.expect(o.segmentId, unittest.equals('foo'));
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
  }
  buildCounterSegment--;
}

buildUnnamed926() {
  var o = new core.List<api.Segment>();
  o.add(buildSegment());
  o.add(buildSegment());
  return o;
}

checkUnnamed926(core.List<api.Segment> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkSegment(o[0]);
  checkSegment(o[1]);
}

core.int buildCounterSegments = 0;
buildSegments() {
  var o = new api.Segments();
  buildCounterSegments++;
  if (buildCounterSegments < 3) {
    o.items = buildUnnamed926();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterSegments--;
  return o;
}

checkSegments(api.Segments o) {
  buildCounterSegments++;
  if (buildCounterSegments < 3) {
    checkUnnamed926(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterSegments--;
}

core.int buildCounterUnsampledReportCloudStorageDownloadDetails = 0;
buildUnsampledReportCloudStorageDownloadDetails() {
  var o = new api.UnsampledReportCloudStorageDownloadDetails();
  buildCounterUnsampledReportCloudStorageDownloadDetails++;
  if (buildCounterUnsampledReportCloudStorageDownloadDetails < 3) {
    o.bucketId = "foo";
    o.objectId = "foo";
  }
  buildCounterUnsampledReportCloudStorageDownloadDetails--;
  return o;
}

checkUnsampledReportCloudStorageDownloadDetails(api.UnsampledReportCloudStorageDownloadDetails o) {
  buildCounterUnsampledReportCloudStorageDownloadDetails++;
  if (buildCounterUnsampledReportCloudStorageDownloadDetails < 3) {
    unittest.expect(o.bucketId, unittest.equals('foo'));
    unittest.expect(o.objectId, unittest.equals('foo'));
  }
  buildCounterUnsampledReportCloudStorageDownloadDetails--;
}

core.int buildCounterUnsampledReportDriveDownloadDetails = 0;
buildUnsampledReportDriveDownloadDetails() {
  var o = new api.UnsampledReportDriveDownloadDetails();
  buildCounterUnsampledReportDriveDownloadDetails++;
  if (buildCounterUnsampledReportDriveDownloadDetails < 3) {
    o.documentId = "foo";
  }
  buildCounterUnsampledReportDriveDownloadDetails--;
  return o;
}

checkUnsampledReportDriveDownloadDetails(api.UnsampledReportDriveDownloadDetails o) {
  buildCounterUnsampledReportDriveDownloadDetails++;
  if (buildCounterUnsampledReportDriveDownloadDetails < 3) {
    unittest.expect(o.documentId, unittest.equals('foo'));
  }
  buildCounterUnsampledReportDriveDownloadDetails--;
}

core.int buildCounterUnsampledReport = 0;
buildUnsampledReport() {
  var o = new api.UnsampledReport();
  buildCounterUnsampledReport++;
  if (buildCounterUnsampledReport < 3) {
    o.accountId = "foo";
    o.cloudStorageDownloadDetails = buildUnsampledReportCloudStorageDownloadDetails();
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.dimensions = "foo";
    o.downloadType = "foo";
    o.driveDownloadDetails = buildUnsampledReportDriveDownloadDetails();
    o.end_date = "foo";
    o.filters = "foo";
    o.id = "foo";
    o.kind = "foo";
    o.metrics = "foo";
    o.profileId = "foo";
    o.segment = "foo";
    o.selfLink = "foo";
    o.start_date = "foo";
    o.status = "foo";
    o.title = "foo";
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
    o.webPropertyId = "foo";
  }
  buildCounterUnsampledReport--;
  return o;
}

checkUnsampledReport(api.UnsampledReport o) {
  buildCounterUnsampledReport++;
  if (buildCounterUnsampledReport < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    checkUnsampledReportCloudStorageDownloadDetails(o.cloudStorageDownloadDetails);
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.dimensions, unittest.equals('foo'));
    unittest.expect(o.downloadType, unittest.equals('foo'));
    checkUnsampledReportDriveDownloadDetails(o.driveDownloadDetails);
    unittest.expect(o.end_date, unittest.equals('foo'));
    unittest.expect(o.filters, unittest.equals('foo'));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.metrics, unittest.equals('foo'));
    unittest.expect(o.profileId, unittest.equals('foo'));
    unittest.expect(o.segment, unittest.equals('foo'));
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.start_date, unittest.equals('foo'));
    unittest.expect(o.status, unittest.equals('foo'));
    unittest.expect(o.title, unittest.equals('foo'));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.webPropertyId, unittest.equals('foo'));
  }
  buildCounterUnsampledReport--;
}

buildUnnamed927() {
  var o = new core.List<api.UnsampledReport>();
  o.add(buildUnsampledReport());
  o.add(buildUnsampledReport());
  return o;
}

checkUnnamed927(core.List<api.UnsampledReport> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkUnsampledReport(o[0]);
  checkUnsampledReport(o[1]);
}

core.int buildCounterUnsampledReports = 0;
buildUnsampledReports() {
  var o = new api.UnsampledReports();
  buildCounterUnsampledReports++;
  if (buildCounterUnsampledReports < 3) {
    o.items = buildUnnamed927();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterUnsampledReports--;
  return o;
}

checkUnsampledReports(api.UnsampledReports o) {
  buildCounterUnsampledReports++;
  if (buildCounterUnsampledReports < 3) {
    checkUnnamed927(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterUnsampledReports--;
}

buildUnnamed928() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed928(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterUpload = 0;
buildUpload() {
  var o = new api.Upload();
  buildCounterUpload++;
  if (buildCounterUpload < 3) {
    o.accountId = "foo";
    o.customDataSourceId = "foo";
    o.errors = buildUnnamed928();
    o.id = "foo";
    o.kind = "foo";
    o.status = "foo";
  }
  buildCounterUpload--;
  return o;
}

checkUpload(api.Upload o) {
  buildCounterUpload++;
  if (buildCounterUpload < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.customDataSourceId, unittest.equals('foo'));
    checkUnnamed928(o.errors);
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.status, unittest.equals('foo'));
  }
  buildCounterUpload--;
}

buildUnnamed929() {
  var o = new core.List<api.Upload>();
  o.add(buildUpload());
  o.add(buildUpload());
  return o;
}

checkUnnamed929(core.List<api.Upload> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkUpload(o[0]);
  checkUpload(o[1]);
}

core.int buildCounterUploads = 0;
buildUploads() {
  var o = new api.Uploads();
  buildCounterUploads++;
  if (buildCounterUploads < 3) {
    o.items = buildUnnamed929();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
  }
  buildCounterUploads--;
  return o;
}

checkUploads(api.Uploads o) {
  buildCounterUploads++;
  if (buildCounterUploads < 3) {
    checkUnnamed929(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
  }
  buildCounterUploads--;
}

core.int buildCounterUserRef = 0;
buildUserRef() {
  var o = new api.UserRef();
  buildCounterUserRef++;
  if (buildCounterUserRef < 3) {
    o.email = "foo";
    o.id = "foo";
    o.kind = "foo";
  }
  buildCounterUserRef--;
  return o;
}

checkUserRef(api.UserRef o) {
  buildCounterUserRef++;
  if (buildCounterUserRef < 3) {
    unittest.expect(o.email, unittest.equals('foo'));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
  }
  buildCounterUserRef--;
}

core.int buildCounterWebPropertyRef = 0;
buildWebPropertyRef() {
  var o = new api.WebPropertyRef();
  buildCounterWebPropertyRef++;
  if (buildCounterWebPropertyRef < 3) {
    o.accountId = "foo";
    o.href = "foo";
    o.id = "foo";
    o.internalWebPropertyId = "foo";
    o.kind = "foo";
    o.name = "foo";
  }
  buildCounterWebPropertyRef--;
  return o;
}

checkWebPropertyRef(api.WebPropertyRef o) {
  buildCounterWebPropertyRef++;
  if (buildCounterWebPropertyRef < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.internalWebPropertyId, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
  }
  buildCounterWebPropertyRef--;
}

buildUnnamed930() {
  var o = new core.List<api.ProfileSummary>();
  o.add(buildProfileSummary());
  o.add(buildProfileSummary());
  return o;
}

checkUnnamed930(core.List<api.ProfileSummary> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkProfileSummary(o[0]);
  checkProfileSummary(o[1]);
}

core.int buildCounterWebPropertySummary = 0;
buildWebPropertySummary() {
  var o = new api.WebPropertySummary();
  buildCounterWebPropertySummary++;
  if (buildCounterWebPropertySummary < 3) {
    o.id = "foo";
    o.internalWebPropertyId = "foo";
    o.kind = "foo";
    o.level = "foo";
    o.name = "foo";
    o.profiles = buildUnnamed930();
    o.websiteUrl = "foo";
  }
  buildCounterWebPropertySummary--;
  return o;
}

checkWebPropertySummary(api.WebPropertySummary o) {
  buildCounterWebPropertySummary++;
  if (buildCounterWebPropertySummary < 3) {
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.internalWebPropertyId, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.level, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    checkUnnamed930(o.profiles);
    unittest.expect(o.websiteUrl, unittest.equals('foo'));
  }
  buildCounterWebPropertySummary--;
}

buildUnnamed931() {
  var o = new core.List<api.Webproperty>();
  o.add(buildWebproperty());
  o.add(buildWebproperty());
  return o;
}

checkUnnamed931(core.List<api.Webproperty> o) {
  unittest.expect(o, unittest.hasLength(2));
  checkWebproperty(o[0]);
  checkWebproperty(o[1]);
}

core.int buildCounterWebproperties = 0;
buildWebproperties() {
  var o = new api.Webproperties();
  buildCounterWebproperties++;
  if (buildCounterWebproperties < 3) {
    o.items = buildUnnamed931();
    o.itemsPerPage = 42;
    o.kind = "foo";
    o.nextLink = "foo";
    o.previousLink = "foo";
    o.startIndex = 42;
    o.totalResults = 42;
    o.username = "foo";
  }
  buildCounterWebproperties--;
  return o;
}

checkWebproperties(api.Webproperties o) {
  buildCounterWebproperties++;
  if (buildCounterWebproperties < 3) {
    checkUnnamed931(o.items);
    unittest.expect(o.itemsPerPage, unittest.equals(42));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.nextLink, unittest.equals('foo'));
    unittest.expect(o.previousLink, unittest.equals('foo'));
    unittest.expect(o.startIndex, unittest.equals(42));
    unittest.expect(o.totalResults, unittest.equals(42));
    unittest.expect(o.username, unittest.equals('foo'));
  }
  buildCounterWebproperties--;
}

core.int buildCounterWebpropertyChildLink = 0;
buildWebpropertyChildLink() {
  var o = new api.WebpropertyChildLink();
  buildCounterWebpropertyChildLink++;
  if (buildCounterWebpropertyChildLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterWebpropertyChildLink--;
  return o;
}

checkWebpropertyChildLink(api.WebpropertyChildLink o) {
  buildCounterWebpropertyChildLink++;
  if (buildCounterWebpropertyChildLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterWebpropertyChildLink--;
}

core.int buildCounterWebpropertyParentLink = 0;
buildWebpropertyParentLink() {
  var o = new api.WebpropertyParentLink();
  buildCounterWebpropertyParentLink++;
  if (buildCounterWebpropertyParentLink < 3) {
    o.href = "foo";
    o.type = "foo";
  }
  buildCounterWebpropertyParentLink--;
  return o;
}

checkWebpropertyParentLink(api.WebpropertyParentLink o) {
  buildCounterWebpropertyParentLink++;
  if (buildCounterWebpropertyParentLink < 3) {
    unittest.expect(o.href, unittest.equals('foo'));
    unittest.expect(o.type, unittest.equals('foo'));
  }
  buildCounterWebpropertyParentLink--;
}

buildUnnamed932() {
  var o = new core.List<core.String>();
  o.add("foo");
  o.add("foo");
  return o;
}

checkUnnamed932(core.List<core.String> o) {
  unittest.expect(o, unittest.hasLength(2));
  unittest.expect(o[0], unittest.equals('foo'));
  unittest.expect(o[1], unittest.equals('foo'));
}

core.int buildCounterWebpropertyPermissions = 0;
buildWebpropertyPermissions() {
  var o = new api.WebpropertyPermissions();
  buildCounterWebpropertyPermissions++;
  if (buildCounterWebpropertyPermissions < 3) {
    o.effective = buildUnnamed932();
  }
  buildCounterWebpropertyPermissions--;
  return o;
}

checkWebpropertyPermissions(api.WebpropertyPermissions o) {
  buildCounterWebpropertyPermissions++;
  if (buildCounterWebpropertyPermissions < 3) {
    checkUnnamed932(o.effective);
  }
  buildCounterWebpropertyPermissions--;
}

core.int buildCounterWebproperty = 0;
buildWebproperty() {
  var o = new api.Webproperty();
  buildCounterWebproperty++;
  if (buildCounterWebproperty < 3) {
    o.accountId = "foo";
    o.childLink = buildWebpropertyChildLink();
    o.created = core.DateTime.parse("2002-02-27T14:01:02");
    o.defaultProfileId = "foo";
    o.id = "foo";
    o.industryVertical = "foo";
    o.internalWebPropertyId = "foo";
    o.kind = "foo";
    o.level = "foo";
    o.name = "foo";
    o.parentLink = buildWebpropertyParentLink();
    o.permissions = buildWebpropertyPermissions();
    o.profileCount = 42;
    o.selfLink = "foo";
    o.updated = core.DateTime.parse("2002-02-27T14:01:02");
    o.websiteUrl = "foo";
  }
  buildCounterWebproperty--;
  return o;
}

checkWebproperty(api.Webproperty o) {
  buildCounterWebproperty++;
  if (buildCounterWebproperty < 3) {
    unittest.expect(o.accountId, unittest.equals('foo'));
    checkWebpropertyChildLink(o.childLink);
    unittest.expect(o.created, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.defaultProfileId, unittest.equals('foo'));
    unittest.expect(o.id, unittest.equals('foo'));
    unittest.expect(o.industryVertical, unittest.equals('foo'));
    unittest.expect(o.internalWebPropertyId, unittest.equals('foo'));
    unittest.expect(o.kind, unittest.equals('foo'));
    unittest.expect(o.level, unittest.equals('foo'));
    unittest.expect(o.name, unittest.equals('foo'));
    checkWebpropertyParentLink(o.parentLink);
    checkWebpropertyPermissions(o.permissions);
    unittest.expect(o.profileCount, unittest.equals(42));
    unittest.expect(o.selfLink, unittest.equals('foo'));
    unittest.expect(o.updated, unittest.equals(core.DateTime.parse("2002-02-27T14:01:02")));
    unittest.expect(o.websiteUrl, unittest.equals('foo'));
  }
  buildCounterWebproperty--;
}


main() {
  unittest.group("obj-schema-AccountChildLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildAccountChildLink();
      var od = new api.AccountChildLink.fromJson(o.toJson());
      checkAccountChildLink(od);
    });
  });


  unittest.group("obj-schema-AccountPermissions", () {
    unittest.test("to-json--from-json", () {
      var o = buildAccountPermissions();
      var od = new api.AccountPermissions.fromJson(o.toJson());
      checkAccountPermissions(od);
    });
  });


  unittest.group("obj-schema-Account", () {
    unittest.test("to-json--from-json", () {
      var o = buildAccount();
      var od = new api.Account.fromJson(o.toJson());
      checkAccount(od);
    });
  });


  unittest.group("obj-schema-AccountRef", () {
    unittest.test("to-json--from-json", () {
      var o = buildAccountRef();
      var od = new api.AccountRef.fromJson(o.toJson());
      checkAccountRef(od);
    });
  });


  unittest.group("obj-schema-AccountSummaries", () {
    unittest.test("to-json--from-json", () {
      var o = buildAccountSummaries();
      var od = new api.AccountSummaries.fromJson(o.toJson());
      checkAccountSummaries(od);
    });
  });


  unittest.group("obj-schema-AccountSummary", () {
    unittest.test("to-json--from-json", () {
      var o = buildAccountSummary();
      var od = new api.AccountSummary.fromJson(o.toJson());
      checkAccountSummary(od);
    });
  });


  unittest.group("obj-schema-AccountTicket", () {
    unittest.test("to-json--from-json", () {
      var o = buildAccountTicket();
      var od = new api.AccountTicket.fromJson(o.toJson());
      checkAccountTicket(od);
    });
  });


  unittest.group("obj-schema-Accounts", () {
    unittest.test("to-json--from-json", () {
      var o = buildAccounts();
      var od = new api.Accounts.fromJson(o.toJson());
      checkAccounts(od);
    });
  });


  unittest.group("obj-schema-AdWordsAccount", () {
    unittest.test("to-json--from-json", () {
      var o = buildAdWordsAccount();
      var od = new api.AdWordsAccount.fromJson(o.toJson());
      checkAdWordsAccount(od);
    });
  });


  unittest.group("obj-schema-AnalyticsDataimportDeleteUploadDataRequest", () {
    unittest.test("to-json--from-json", () {
      var o = buildAnalyticsDataimportDeleteUploadDataRequest();
      var od = new api.AnalyticsDataimportDeleteUploadDataRequest.fromJson(o.toJson());
      checkAnalyticsDataimportDeleteUploadDataRequest(od);
    });
  });


  unittest.group("obj-schema-Column", () {
    unittest.test("to-json--from-json", () {
      var o = buildColumn();
      var od = new api.Column.fromJson(o.toJson());
      checkColumn(od);
    });
  });


  unittest.group("obj-schema-Columns", () {
    unittest.test("to-json--from-json", () {
      var o = buildColumns();
      var od = new api.Columns.fromJson(o.toJson());
      checkColumns(od);
    });
  });


  unittest.group("obj-schema-CustomDataSourceChildLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildCustomDataSourceChildLink();
      var od = new api.CustomDataSourceChildLink.fromJson(o.toJson());
      checkCustomDataSourceChildLink(od);
    });
  });


  unittest.group("obj-schema-CustomDataSourceParentLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildCustomDataSourceParentLink();
      var od = new api.CustomDataSourceParentLink.fromJson(o.toJson());
      checkCustomDataSourceParentLink(od);
    });
  });


  unittest.group("obj-schema-CustomDataSource", () {
    unittest.test("to-json--from-json", () {
      var o = buildCustomDataSource();
      var od = new api.CustomDataSource.fromJson(o.toJson());
      checkCustomDataSource(od);
    });
  });


  unittest.group("obj-schema-CustomDataSources", () {
    unittest.test("to-json--from-json", () {
      var o = buildCustomDataSources();
      var od = new api.CustomDataSources.fromJson(o.toJson());
      checkCustomDataSources(od);
    });
  });


  unittest.group("obj-schema-CustomDimensionParentLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildCustomDimensionParentLink();
      var od = new api.CustomDimensionParentLink.fromJson(o.toJson());
      checkCustomDimensionParentLink(od);
    });
  });


  unittest.group("obj-schema-CustomDimension", () {
    unittest.test("to-json--from-json", () {
      var o = buildCustomDimension();
      var od = new api.CustomDimension.fromJson(o.toJson());
      checkCustomDimension(od);
    });
  });


  unittest.group("obj-schema-CustomDimensions", () {
    unittest.test("to-json--from-json", () {
      var o = buildCustomDimensions();
      var od = new api.CustomDimensions.fromJson(o.toJson());
      checkCustomDimensions(od);
    });
  });


  unittest.group("obj-schema-CustomMetricParentLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildCustomMetricParentLink();
      var od = new api.CustomMetricParentLink.fromJson(o.toJson());
      checkCustomMetricParentLink(od);
    });
  });


  unittest.group("obj-schema-CustomMetric", () {
    unittest.test("to-json--from-json", () {
      var o = buildCustomMetric();
      var od = new api.CustomMetric.fromJson(o.toJson());
      checkCustomMetric(od);
    });
  });


  unittest.group("obj-schema-CustomMetrics", () {
    unittest.test("to-json--from-json", () {
      var o = buildCustomMetrics();
      var od = new api.CustomMetrics.fromJson(o.toJson());
      checkCustomMetrics(od);
    });
  });


  unittest.group("obj-schema-EntityAdWordsLinkEntity", () {
    unittest.test("to-json--from-json", () {
      var o = buildEntityAdWordsLinkEntity();
      var od = new api.EntityAdWordsLinkEntity.fromJson(o.toJson());
      checkEntityAdWordsLinkEntity(od);
    });
  });


  unittest.group("obj-schema-EntityAdWordsLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildEntityAdWordsLink();
      var od = new api.EntityAdWordsLink.fromJson(o.toJson());
      checkEntityAdWordsLink(od);
    });
  });


  unittest.group("obj-schema-EntityAdWordsLinks", () {
    unittest.test("to-json--from-json", () {
      var o = buildEntityAdWordsLinks();
      var od = new api.EntityAdWordsLinks.fromJson(o.toJson());
      checkEntityAdWordsLinks(od);
    });
  });


  unittest.group("obj-schema-EntityUserLinkEntity", () {
    unittest.test("to-json--from-json", () {
      var o = buildEntityUserLinkEntity();
      var od = new api.EntityUserLinkEntity.fromJson(o.toJson());
      checkEntityUserLinkEntity(od);
    });
  });


  unittest.group("obj-schema-EntityUserLinkPermissions", () {
    unittest.test("to-json--from-json", () {
      var o = buildEntityUserLinkPermissions();
      var od = new api.EntityUserLinkPermissions.fromJson(o.toJson());
      checkEntityUserLinkPermissions(od);
    });
  });


  unittest.group("obj-schema-EntityUserLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildEntityUserLink();
      var od = new api.EntityUserLink.fromJson(o.toJson());
      checkEntityUserLink(od);
    });
  });


  unittest.group("obj-schema-EntityUserLinks", () {
    unittest.test("to-json--from-json", () {
      var o = buildEntityUserLinks();
      var od = new api.EntityUserLinks.fromJson(o.toJson());
      checkEntityUserLinks(od);
    });
  });


  unittest.group("obj-schema-ExperimentParentLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildExperimentParentLink();
      var od = new api.ExperimentParentLink.fromJson(o.toJson());
      checkExperimentParentLink(od);
    });
  });


  unittest.group("obj-schema-ExperimentVariations", () {
    unittest.test("to-json--from-json", () {
      var o = buildExperimentVariations();
      var od = new api.ExperimentVariations.fromJson(o.toJson());
      checkExperimentVariations(od);
    });
  });


  unittest.group("obj-schema-Experiment", () {
    unittest.test("to-json--from-json", () {
      var o = buildExperiment();
      var od = new api.Experiment.fromJson(o.toJson());
      checkExperiment(od);
    });
  });


  unittest.group("obj-schema-Experiments", () {
    unittest.test("to-json--from-json", () {
      var o = buildExperiments();
      var od = new api.Experiments.fromJson(o.toJson());
      checkExperiments(od);
    });
  });


  unittest.group("obj-schema-FilterAdvancedDetails", () {
    unittest.test("to-json--from-json", () {
      var o = buildFilterAdvancedDetails();
      var od = new api.FilterAdvancedDetails.fromJson(o.toJson());
      checkFilterAdvancedDetails(od);
    });
  });


  unittest.group("obj-schema-FilterLowercaseDetails", () {
    unittest.test("to-json--from-json", () {
      var o = buildFilterLowercaseDetails();
      var od = new api.FilterLowercaseDetails.fromJson(o.toJson());
      checkFilterLowercaseDetails(od);
    });
  });


  unittest.group("obj-schema-FilterParentLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildFilterParentLink();
      var od = new api.FilterParentLink.fromJson(o.toJson());
      checkFilterParentLink(od);
    });
  });


  unittest.group("obj-schema-FilterSearchAndReplaceDetails", () {
    unittest.test("to-json--from-json", () {
      var o = buildFilterSearchAndReplaceDetails();
      var od = new api.FilterSearchAndReplaceDetails.fromJson(o.toJson());
      checkFilterSearchAndReplaceDetails(od);
    });
  });


  unittest.group("obj-schema-FilterUppercaseDetails", () {
    unittest.test("to-json--from-json", () {
      var o = buildFilterUppercaseDetails();
      var od = new api.FilterUppercaseDetails.fromJson(o.toJson());
      checkFilterUppercaseDetails(od);
    });
  });


  unittest.group("obj-schema-Filter", () {
    unittest.test("to-json--from-json", () {
      var o = buildFilter();
      var od = new api.Filter.fromJson(o.toJson());
      checkFilter(od);
    });
  });


  unittest.group("obj-schema-FilterExpression", () {
    unittest.test("to-json--from-json", () {
      var o = buildFilterExpression();
      var od = new api.FilterExpression.fromJson(o.toJson());
      checkFilterExpression(od);
    });
  });


  unittest.group("obj-schema-FilterRef", () {
    unittest.test("to-json--from-json", () {
      var o = buildFilterRef();
      var od = new api.FilterRef.fromJson(o.toJson());
      checkFilterRef(od);
    });
  });


  unittest.group("obj-schema-Filters", () {
    unittest.test("to-json--from-json", () {
      var o = buildFilters();
      var od = new api.Filters.fromJson(o.toJson());
      checkFilters(od);
    });
  });


  unittest.group("obj-schema-GaDataColumnHeaders", () {
    unittest.test("to-json--from-json", () {
      var o = buildGaDataColumnHeaders();
      var od = new api.GaDataColumnHeaders.fromJson(o.toJson());
      checkGaDataColumnHeaders(od);
    });
  });


  unittest.group("obj-schema-GaDataDataTableCols", () {
    unittest.test("to-json--from-json", () {
      var o = buildGaDataDataTableCols();
      var od = new api.GaDataDataTableCols.fromJson(o.toJson());
      checkGaDataDataTableCols(od);
    });
  });


  unittest.group("obj-schema-GaDataDataTableRowsC", () {
    unittest.test("to-json--from-json", () {
      var o = buildGaDataDataTableRowsC();
      var od = new api.GaDataDataTableRowsC.fromJson(o.toJson());
      checkGaDataDataTableRowsC(od);
    });
  });


  unittest.group("obj-schema-GaDataDataTableRows", () {
    unittest.test("to-json--from-json", () {
      var o = buildGaDataDataTableRows();
      var od = new api.GaDataDataTableRows.fromJson(o.toJson());
      checkGaDataDataTableRows(od);
    });
  });


  unittest.group("obj-schema-GaDataDataTable", () {
    unittest.test("to-json--from-json", () {
      var o = buildGaDataDataTable();
      var od = new api.GaDataDataTable.fromJson(o.toJson());
      checkGaDataDataTable(od);
    });
  });


  unittest.group("obj-schema-GaDataProfileInfo", () {
    unittest.test("to-json--from-json", () {
      var o = buildGaDataProfileInfo();
      var od = new api.GaDataProfileInfo.fromJson(o.toJson());
      checkGaDataProfileInfo(od);
    });
  });


  unittest.group("obj-schema-GaDataQuery", () {
    unittest.test("to-json--from-json", () {
      var o = buildGaDataQuery();
      var od = new api.GaDataQuery.fromJson(o.toJson());
      checkGaDataQuery(od);
    });
  });


  unittest.group("obj-schema-GaData", () {
    unittest.test("to-json--from-json", () {
      var o = buildGaData();
      var od = new api.GaData.fromJson(o.toJson());
      checkGaData(od);
    });
  });


  unittest.group("obj-schema-GoalEventDetailsEventConditions", () {
    unittest.test("to-json--from-json", () {
      var o = buildGoalEventDetailsEventConditions();
      var od = new api.GoalEventDetailsEventConditions.fromJson(o.toJson());
      checkGoalEventDetailsEventConditions(od);
    });
  });


  unittest.group("obj-schema-GoalEventDetails", () {
    unittest.test("to-json--from-json", () {
      var o = buildGoalEventDetails();
      var od = new api.GoalEventDetails.fromJson(o.toJson());
      checkGoalEventDetails(od);
    });
  });


  unittest.group("obj-schema-GoalParentLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildGoalParentLink();
      var od = new api.GoalParentLink.fromJson(o.toJson());
      checkGoalParentLink(od);
    });
  });


  unittest.group("obj-schema-GoalUrlDestinationDetailsSteps", () {
    unittest.test("to-json--from-json", () {
      var o = buildGoalUrlDestinationDetailsSteps();
      var od = new api.GoalUrlDestinationDetailsSteps.fromJson(o.toJson());
      checkGoalUrlDestinationDetailsSteps(od);
    });
  });


  unittest.group("obj-schema-GoalUrlDestinationDetails", () {
    unittest.test("to-json--from-json", () {
      var o = buildGoalUrlDestinationDetails();
      var od = new api.GoalUrlDestinationDetails.fromJson(o.toJson());
      checkGoalUrlDestinationDetails(od);
    });
  });


  unittest.group("obj-schema-GoalVisitNumPagesDetails", () {
    unittest.test("to-json--from-json", () {
      var o = buildGoalVisitNumPagesDetails();
      var od = new api.GoalVisitNumPagesDetails.fromJson(o.toJson());
      checkGoalVisitNumPagesDetails(od);
    });
  });


  unittest.group("obj-schema-GoalVisitTimeOnSiteDetails", () {
    unittest.test("to-json--from-json", () {
      var o = buildGoalVisitTimeOnSiteDetails();
      var od = new api.GoalVisitTimeOnSiteDetails.fromJson(o.toJson());
      checkGoalVisitTimeOnSiteDetails(od);
    });
  });


  unittest.group("obj-schema-Goal", () {
    unittest.test("to-json--from-json", () {
      var o = buildGoal();
      var od = new api.Goal.fromJson(o.toJson());
      checkGoal(od);
    });
  });


  unittest.group("obj-schema-Goals", () {
    unittest.test("to-json--from-json", () {
      var o = buildGoals();
      var od = new api.Goals.fromJson(o.toJson());
      checkGoals(od);
    });
  });


  unittest.group("obj-schema-McfDataColumnHeaders", () {
    unittest.test("to-json--from-json", () {
      var o = buildMcfDataColumnHeaders();
      var od = new api.McfDataColumnHeaders.fromJson(o.toJson());
      checkMcfDataColumnHeaders(od);
    });
  });


  unittest.group("obj-schema-McfDataProfileInfo", () {
    unittest.test("to-json--from-json", () {
      var o = buildMcfDataProfileInfo();
      var od = new api.McfDataProfileInfo.fromJson(o.toJson());
      checkMcfDataProfileInfo(od);
    });
  });


  unittest.group("obj-schema-McfDataQuery", () {
    unittest.test("to-json--from-json", () {
      var o = buildMcfDataQuery();
      var od = new api.McfDataQuery.fromJson(o.toJson());
      checkMcfDataQuery(od);
    });
  });


  unittest.group("obj-schema-McfDataRowsConversionPathValue", () {
    unittest.test("to-json--from-json", () {
      var o = buildMcfDataRowsConversionPathValue();
      var od = new api.McfDataRowsConversionPathValue.fromJson(o.toJson());
      checkMcfDataRowsConversionPathValue(od);
    });
  });


  unittest.group("obj-schema-McfDataRows", () {
    unittest.test("to-json--from-json", () {
      var o = buildMcfDataRows();
      var od = new api.McfDataRows.fromJson(o.toJson());
      checkMcfDataRows(od);
    });
  });


  unittest.group("obj-schema-McfData", () {
    unittest.test("to-json--from-json", () {
      var o = buildMcfData();
      var od = new api.McfData.fromJson(o.toJson());
      checkMcfData(od);
    });
  });


  unittest.group("obj-schema-ProfileChildLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildProfileChildLink();
      var od = new api.ProfileChildLink.fromJson(o.toJson());
      checkProfileChildLink(od);
    });
  });


  unittest.group("obj-schema-ProfileParentLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildProfileParentLink();
      var od = new api.ProfileParentLink.fromJson(o.toJson());
      checkProfileParentLink(od);
    });
  });


  unittest.group("obj-schema-ProfilePermissions", () {
    unittest.test("to-json--from-json", () {
      var o = buildProfilePermissions();
      var od = new api.ProfilePermissions.fromJson(o.toJson());
      checkProfilePermissions(od);
    });
  });


  unittest.group("obj-schema-Profile", () {
    unittest.test("to-json--from-json", () {
      var o = buildProfile();
      var od = new api.Profile.fromJson(o.toJson());
      checkProfile(od);
    });
  });


  unittest.group("obj-schema-ProfileFilterLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildProfileFilterLink();
      var od = new api.ProfileFilterLink.fromJson(o.toJson());
      checkProfileFilterLink(od);
    });
  });


  unittest.group("obj-schema-ProfileFilterLinks", () {
    unittest.test("to-json--from-json", () {
      var o = buildProfileFilterLinks();
      var od = new api.ProfileFilterLinks.fromJson(o.toJson());
      checkProfileFilterLinks(od);
    });
  });


  unittest.group("obj-schema-ProfileRef", () {
    unittest.test("to-json--from-json", () {
      var o = buildProfileRef();
      var od = new api.ProfileRef.fromJson(o.toJson());
      checkProfileRef(od);
    });
  });


  unittest.group("obj-schema-ProfileSummary", () {
    unittest.test("to-json--from-json", () {
      var o = buildProfileSummary();
      var od = new api.ProfileSummary.fromJson(o.toJson());
      checkProfileSummary(od);
    });
  });


  unittest.group("obj-schema-Profiles", () {
    unittest.test("to-json--from-json", () {
      var o = buildProfiles();
      var od = new api.Profiles.fromJson(o.toJson());
      checkProfiles(od);
    });
  });


  unittest.group("obj-schema-RealtimeDataColumnHeaders", () {
    unittest.test("to-json--from-json", () {
      var o = buildRealtimeDataColumnHeaders();
      var od = new api.RealtimeDataColumnHeaders.fromJson(o.toJson());
      checkRealtimeDataColumnHeaders(od);
    });
  });


  unittest.group("obj-schema-RealtimeDataProfileInfo", () {
    unittest.test("to-json--from-json", () {
      var o = buildRealtimeDataProfileInfo();
      var od = new api.RealtimeDataProfileInfo.fromJson(o.toJson());
      checkRealtimeDataProfileInfo(od);
    });
  });


  unittest.group("obj-schema-RealtimeDataQuery", () {
    unittest.test("to-json--from-json", () {
      var o = buildRealtimeDataQuery();
      var od = new api.RealtimeDataQuery.fromJson(o.toJson());
      checkRealtimeDataQuery(od);
    });
  });


  unittest.group("obj-schema-RealtimeData", () {
    unittest.test("to-json--from-json", () {
      var o = buildRealtimeData();
      var od = new api.RealtimeData.fromJson(o.toJson());
      checkRealtimeData(od);
    });
  });


  unittest.group("obj-schema-Segment", () {
    unittest.test("to-json--from-json", () {
      var o = buildSegment();
      var od = new api.Segment.fromJson(o.toJson());
      checkSegment(od);
    });
  });


  unittest.group("obj-schema-Segments", () {
    unittest.test("to-json--from-json", () {
      var o = buildSegments();
      var od = new api.Segments.fromJson(o.toJson());
      checkSegments(od);
    });
  });


  unittest.group("obj-schema-UnsampledReportCloudStorageDownloadDetails", () {
    unittest.test("to-json--from-json", () {
      var o = buildUnsampledReportCloudStorageDownloadDetails();
      var od = new api.UnsampledReportCloudStorageDownloadDetails.fromJson(o.toJson());
      checkUnsampledReportCloudStorageDownloadDetails(od);
    });
  });


  unittest.group("obj-schema-UnsampledReportDriveDownloadDetails", () {
    unittest.test("to-json--from-json", () {
      var o = buildUnsampledReportDriveDownloadDetails();
      var od = new api.UnsampledReportDriveDownloadDetails.fromJson(o.toJson());
      checkUnsampledReportDriveDownloadDetails(od);
    });
  });


  unittest.group("obj-schema-UnsampledReport", () {
    unittest.test("to-json--from-json", () {
      var o = buildUnsampledReport();
      var od = new api.UnsampledReport.fromJson(o.toJson());
      checkUnsampledReport(od);
    });
  });


  unittest.group("obj-schema-UnsampledReports", () {
    unittest.test("to-json--from-json", () {
      var o = buildUnsampledReports();
      var od = new api.UnsampledReports.fromJson(o.toJson());
      checkUnsampledReports(od);
    });
  });


  unittest.group("obj-schema-Upload", () {
    unittest.test("to-json--from-json", () {
      var o = buildUpload();
      var od = new api.Upload.fromJson(o.toJson());
      checkUpload(od);
    });
  });


  unittest.group("obj-schema-Uploads", () {
    unittest.test("to-json--from-json", () {
      var o = buildUploads();
      var od = new api.Uploads.fromJson(o.toJson());
      checkUploads(od);
    });
  });


  unittest.group("obj-schema-UserRef", () {
    unittest.test("to-json--from-json", () {
      var o = buildUserRef();
      var od = new api.UserRef.fromJson(o.toJson());
      checkUserRef(od);
    });
  });


  unittest.group("obj-schema-WebPropertyRef", () {
    unittest.test("to-json--from-json", () {
      var o = buildWebPropertyRef();
      var od = new api.WebPropertyRef.fromJson(o.toJson());
      checkWebPropertyRef(od);
    });
  });


  unittest.group("obj-schema-WebPropertySummary", () {
    unittest.test("to-json--from-json", () {
      var o = buildWebPropertySummary();
      var od = new api.WebPropertySummary.fromJson(o.toJson());
      checkWebPropertySummary(od);
    });
  });


  unittest.group("obj-schema-Webproperties", () {
    unittest.test("to-json--from-json", () {
      var o = buildWebproperties();
      var od = new api.Webproperties.fromJson(o.toJson());
      checkWebproperties(od);
    });
  });


  unittest.group("obj-schema-WebpropertyChildLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildWebpropertyChildLink();
      var od = new api.WebpropertyChildLink.fromJson(o.toJson());
      checkWebpropertyChildLink(od);
    });
  });


  unittest.group("obj-schema-WebpropertyParentLink", () {
    unittest.test("to-json--from-json", () {
      var o = buildWebpropertyParentLink();
      var od = new api.WebpropertyParentLink.fromJson(o.toJson());
      checkWebpropertyParentLink(od);
    });
  });


  unittest.group("obj-schema-WebpropertyPermissions", () {
    unittest.test("to-json--from-json", () {
      var o = buildWebpropertyPermissions();
      var od = new api.WebpropertyPermissions.fromJson(o.toJson());
      checkWebpropertyPermissions(od);
    });
  });


  unittest.group("obj-schema-Webproperty", () {
    unittest.test("to-json--from-json", () {
      var o = buildWebproperty();
      var od = new api.Webproperty.fromJson(o.toJson());
      checkWebproperty(od);
    });
  });


  unittest.group("resource-DataGaResourceApi", () {
    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.DataGaResourceApi res = new api.AnalyticsApi(mock).data.ga;
      var arg_ids = "foo";
      var arg_start_date = "foo";
      var arg_end_date = "foo";
      var arg_metrics = "foo";
      var arg_dimensions = "foo";
      var arg_filters = "foo";
      var arg_max_results = 42;
      var arg_output = "foo";
      var arg_samplingLevel = "foo";
      var arg_segment = "foo";
      var arg_sort = "foo";
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 7), unittest.equals("data/ga"));
        pathOffset += 7;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(queryMap["ids"].first, unittest.equals(arg_ids));
        unittest.expect(queryMap["start-date"].first, unittest.equals(arg_start_date));
        unittest.expect(queryMap["end-date"].first, unittest.equals(arg_end_date));
        unittest.expect(queryMap["metrics"].first, unittest.equals(arg_metrics));
        unittest.expect(queryMap["dimensions"].first, unittest.equals(arg_dimensions));
        unittest.expect(queryMap["filters"].first, unittest.equals(arg_filters));
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(queryMap["output"].first, unittest.equals(arg_output));
        unittest.expect(queryMap["samplingLevel"].first, unittest.equals(arg_samplingLevel));
        unittest.expect(queryMap["segment"].first, unittest.equals(arg_segment));
        unittest.expect(queryMap["sort"].first, unittest.equals(arg_sort));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildGaData());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_ids, arg_start_date, arg_end_date, arg_metrics, dimensions: arg_dimensions, filters: arg_filters, max_results: arg_max_results, output: arg_output, samplingLevel: arg_samplingLevel, segment: arg_segment, sort: arg_sort, start_index: arg_start_index).then(unittest.expectAsync(((api.GaData response) {
        checkGaData(response);
      })));
    });

  });


  unittest.group("resource-DataMcfResourceApi", () {
    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.DataMcfResourceApi res = new api.AnalyticsApi(mock).data.mcf;
      var arg_ids = "foo";
      var arg_start_date = "foo";
      var arg_end_date = "foo";
      var arg_metrics = "foo";
      var arg_dimensions = "foo";
      var arg_filters = "foo";
      var arg_max_results = 42;
      var arg_samplingLevel = "foo";
      var arg_sort = "foo";
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 8), unittest.equals("data/mcf"));
        pathOffset += 8;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(queryMap["ids"].first, unittest.equals(arg_ids));
        unittest.expect(queryMap["start-date"].first, unittest.equals(arg_start_date));
        unittest.expect(queryMap["end-date"].first, unittest.equals(arg_end_date));
        unittest.expect(queryMap["metrics"].first, unittest.equals(arg_metrics));
        unittest.expect(queryMap["dimensions"].first, unittest.equals(arg_dimensions));
        unittest.expect(queryMap["filters"].first, unittest.equals(arg_filters));
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(queryMap["samplingLevel"].first, unittest.equals(arg_samplingLevel));
        unittest.expect(queryMap["sort"].first, unittest.equals(arg_sort));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildMcfData());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_ids, arg_start_date, arg_end_date, arg_metrics, dimensions: arg_dimensions, filters: arg_filters, max_results: arg_max_results, samplingLevel: arg_samplingLevel, sort: arg_sort, start_index: arg_start_index).then(unittest.expectAsync(((api.McfData response) {
        checkMcfData(response);
      })));
    });

  });


  unittest.group("resource-DataRealtimeResourceApi", () {
    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.DataRealtimeResourceApi res = new api.AnalyticsApi(mock).data.realtime;
      var arg_ids = "foo";
      var arg_metrics = "foo";
      var arg_dimensions = "foo";
      var arg_filters = "foo";
      var arg_max_results = 42;
      var arg_sort = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("data/realtime"));
        pathOffset += 13;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(queryMap["ids"].first, unittest.equals(arg_ids));
        unittest.expect(queryMap["metrics"].first, unittest.equals(arg_metrics));
        unittest.expect(queryMap["dimensions"].first, unittest.equals(arg_dimensions));
        unittest.expect(queryMap["filters"].first, unittest.equals(arg_filters));
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(queryMap["sort"].first, unittest.equals(arg_sort));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildRealtimeData());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_ids, arg_metrics, dimensions: arg_dimensions, filters: arg_filters, max_results: arg_max_results, sort: arg_sort).then(unittest.expectAsync(((api.RealtimeData response) {
        checkRealtimeData(response);
      })));
    });

  });


  unittest.group("resource-ManagementAccountSummariesResourceApi", () {
    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementAccountSummariesResourceApi res = new api.AnalyticsApi(mock).management.accountSummaries;
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 27), unittest.equals("management/accountSummaries"));
        pathOffset += 27;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildAccountSummaries());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.AccountSummaries response) {
        checkAccountSummaries(response);
      })));
    });

  });


  unittest.group("resource-ManagementAccountUserLinksResourceApi", () {
    unittest.test("method--delete", () {

      var mock = new HttpServerMock();
      api.ManagementAccountUserLinksResourceApi res = new api.AnalyticsApi(mock).management.accountUserLinks;
      var arg_accountId = "foo";
      var arg_linkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/entityUserLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/entityUserLinks/"));
        pathOffset += 17;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_linkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = "";
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.delete(arg_accountId, arg_linkId).then(unittest.expectAsync((_) {}));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementAccountUserLinksResourceApi res = new api.AnalyticsApi(mock).management.accountUserLinks;
      var arg_request = buildEntityUserLink();
      var arg_accountId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.EntityUserLink.fromJson(json);
        checkEntityUserLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/entityUserLinks", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 16), unittest.equals("/entityUserLinks"));
        pathOffset += 16;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityUserLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId).then(unittest.expectAsync(((api.EntityUserLink response) {
        checkEntityUserLink(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementAccountUserLinksResourceApi res = new api.AnalyticsApi(mock).management.accountUserLinks;
      var arg_accountId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/entityUserLinks", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 16), unittest.equals("/entityUserLinks"));
        pathOffset += 16;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityUserLinks());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.EntityUserLinks response) {
        checkEntityUserLinks(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementAccountUserLinksResourceApi res = new api.AnalyticsApi(mock).management.accountUserLinks;
      var arg_request = buildEntityUserLink();
      var arg_accountId = "foo";
      var arg_linkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.EntityUserLink.fromJson(json);
        checkEntityUserLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/entityUserLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/entityUserLinks/"));
        pathOffset += 17;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_linkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityUserLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_linkId).then(unittest.expectAsync(((api.EntityUserLink response) {
        checkEntityUserLink(response);
      })));
    });

  });


  unittest.group("resource-ManagementAccountsResourceApi", () {
    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementAccountsResourceApi res = new api.AnalyticsApi(mock).management.accounts;
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 19), unittest.equals("management/accounts"));
        pathOffset += 19;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildAccounts());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.Accounts response) {
        checkAccounts(response);
      })));
    });

  });


  unittest.group("resource-ManagementCustomDataSourcesResourceApi", () {
    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementCustomDataSourcesResourceApi res = new api.AnalyticsApi(mock).management.customDataSources;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customDataSources", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 18), unittest.equals("/customDataSources"));
        pathOffset += 18;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomDataSources());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.CustomDataSources response) {
        checkCustomDataSources(response);
      })));
    });

  });


  unittest.group("resource-ManagementCustomDimensionsResourceApi", () {
    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementCustomDimensionsResourceApi res = new api.AnalyticsApi(mock).management.customDimensions;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_customDimensionId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customDimensions/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 18), unittest.equals("/customDimensions/"));
        pathOffset += 18;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_customDimensionId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomDimension());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_webPropertyId, arg_customDimensionId).then(unittest.expectAsync(((api.CustomDimension response) {
        checkCustomDimension(response);
      })));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementCustomDimensionsResourceApi res = new api.AnalyticsApi(mock).management.customDimensions;
      var arg_request = buildCustomDimension();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.CustomDimension.fromJson(json);
        checkCustomDimension(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customDimensions", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/customDimensions"));
        pathOffset += 17;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomDimension());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId, arg_webPropertyId).then(unittest.expectAsync(((api.CustomDimension response) {
        checkCustomDimension(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementCustomDimensionsResourceApi res = new api.AnalyticsApi(mock).management.customDimensions;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customDimensions", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/customDimensions"));
        pathOffset += 17;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomDimensions());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.CustomDimensions response) {
        checkCustomDimensions(response);
      })));
    });

    unittest.test("method--patch", () {

      var mock = new HttpServerMock();
      api.ManagementCustomDimensionsResourceApi res = new api.AnalyticsApi(mock).management.customDimensions;
      var arg_request = buildCustomDimension();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_customDimensionId = "foo";
      var arg_ignoreCustomDataSourceLinks = true;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.CustomDimension.fromJson(json);
        checkCustomDimension(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customDimensions/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 18), unittest.equals("/customDimensions/"));
        pathOffset += 18;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_customDimensionId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(queryMap["ignoreCustomDataSourceLinks"].first, unittest.equals("$arg_ignoreCustomDataSourceLinks"));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomDimension());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.patch(arg_request, arg_accountId, arg_webPropertyId, arg_customDimensionId, ignoreCustomDataSourceLinks: arg_ignoreCustomDataSourceLinks).then(unittest.expectAsync(((api.CustomDimension response) {
        checkCustomDimension(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementCustomDimensionsResourceApi res = new api.AnalyticsApi(mock).management.customDimensions;
      var arg_request = buildCustomDimension();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_customDimensionId = "foo";
      var arg_ignoreCustomDataSourceLinks = true;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.CustomDimension.fromJson(json);
        checkCustomDimension(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customDimensions/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 18), unittest.equals("/customDimensions/"));
        pathOffset += 18;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_customDimensionId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(queryMap["ignoreCustomDataSourceLinks"].first, unittest.equals("$arg_ignoreCustomDataSourceLinks"));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomDimension());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_webPropertyId, arg_customDimensionId, ignoreCustomDataSourceLinks: arg_ignoreCustomDataSourceLinks).then(unittest.expectAsync(((api.CustomDimension response) {
        checkCustomDimension(response);
      })));
    });

  });


  unittest.group("resource-ManagementCustomMetricsResourceApi", () {
    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementCustomMetricsResourceApi res = new api.AnalyticsApi(mock).management.customMetrics;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_customMetricId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customMetrics/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/customMetrics/"));
        pathOffset += 15;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_customMetricId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomMetric());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_webPropertyId, arg_customMetricId).then(unittest.expectAsync(((api.CustomMetric response) {
        checkCustomMetric(response);
      })));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementCustomMetricsResourceApi res = new api.AnalyticsApi(mock).management.customMetrics;
      var arg_request = buildCustomMetric();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.CustomMetric.fromJson(json);
        checkCustomMetric(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customMetrics", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 14), unittest.equals("/customMetrics"));
        pathOffset += 14;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomMetric());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId, arg_webPropertyId).then(unittest.expectAsync(((api.CustomMetric response) {
        checkCustomMetric(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementCustomMetricsResourceApi res = new api.AnalyticsApi(mock).management.customMetrics;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customMetrics", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 14), unittest.equals("/customMetrics"));
        pathOffset += 14;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomMetrics());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.CustomMetrics response) {
        checkCustomMetrics(response);
      })));
    });

    unittest.test("method--patch", () {

      var mock = new HttpServerMock();
      api.ManagementCustomMetricsResourceApi res = new api.AnalyticsApi(mock).management.customMetrics;
      var arg_request = buildCustomMetric();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_customMetricId = "foo";
      var arg_ignoreCustomDataSourceLinks = true;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.CustomMetric.fromJson(json);
        checkCustomMetric(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customMetrics/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/customMetrics/"));
        pathOffset += 15;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_customMetricId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(queryMap["ignoreCustomDataSourceLinks"].first, unittest.equals("$arg_ignoreCustomDataSourceLinks"));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomMetric());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.patch(arg_request, arg_accountId, arg_webPropertyId, arg_customMetricId, ignoreCustomDataSourceLinks: arg_ignoreCustomDataSourceLinks).then(unittest.expectAsync(((api.CustomMetric response) {
        checkCustomMetric(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementCustomMetricsResourceApi res = new api.AnalyticsApi(mock).management.customMetrics;
      var arg_request = buildCustomMetric();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_customMetricId = "foo";
      var arg_ignoreCustomDataSourceLinks = true;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.CustomMetric.fromJson(json);
        checkCustomMetric(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customMetrics/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/customMetrics/"));
        pathOffset += 15;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_customMetricId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(queryMap["ignoreCustomDataSourceLinks"].first, unittest.equals("$arg_ignoreCustomDataSourceLinks"));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildCustomMetric());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_webPropertyId, arg_customMetricId, ignoreCustomDataSourceLinks: arg_ignoreCustomDataSourceLinks).then(unittest.expectAsync(((api.CustomMetric response) {
        checkCustomMetric(response);
      })));
    });

  });


  unittest.group("resource-ManagementExperimentsResourceApi", () {
    unittest.test("method--delete", () {

      var mock = new HttpServerMock();
      api.ManagementExperimentsResourceApi res = new api.AnalyticsApi(mock).management.experiments;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_experimentId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/experiments/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("/experiments/"));
        pathOffset += 13;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_experimentId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = "";
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.delete(arg_accountId, arg_webPropertyId, arg_profileId, arg_experimentId).then(unittest.expectAsync((_) {}));
    });

    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementExperimentsResourceApi res = new api.AnalyticsApi(mock).management.experiments;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_experimentId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/experiments/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("/experiments/"));
        pathOffset += 13;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_experimentId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildExperiment());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_webPropertyId, arg_profileId, arg_experimentId).then(unittest.expectAsync(((api.Experiment response) {
        checkExperiment(response);
      })));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementExperimentsResourceApi res = new api.AnalyticsApi(mock).management.experiments;
      var arg_request = buildExperiment();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Experiment.fromJson(json);
        checkExperiment(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/experiments", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 12), unittest.equals("/experiments"));
        pathOffset += 12;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildExperiment());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId, arg_webPropertyId, arg_profileId).then(unittest.expectAsync(((api.Experiment response) {
        checkExperiment(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementExperimentsResourceApi res = new api.AnalyticsApi(mock).management.experiments;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/experiments", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 12), unittest.equals("/experiments"));
        pathOffset += 12;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildExperiments());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, arg_profileId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.Experiments response) {
        checkExperiments(response);
      })));
    });

    unittest.test("method--patch", () {

      var mock = new HttpServerMock();
      api.ManagementExperimentsResourceApi res = new api.AnalyticsApi(mock).management.experiments;
      var arg_request = buildExperiment();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_experimentId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Experiment.fromJson(json);
        checkExperiment(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/experiments/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("/experiments/"));
        pathOffset += 13;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_experimentId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildExperiment());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.patch(arg_request, arg_accountId, arg_webPropertyId, arg_profileId, arg_experimentId).then(unittest.expectAsync(((api.Experiment response) {
        checkExperiment(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementExperimentsResourceApi res = new api.AnalyticsApi(mock).management.experiments;
      var arg_request = buildExperiment();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_experimentId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Experiment.fromJson(json);
        checkExperiment(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/experiments/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("/experiments/"));
        pathOffset += 13;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_experimentId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildExperiment());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_webPropertyId, arg_profileId, arg_experimentId).then(unittest.expectAsync(((api.Experiment response) {
        checkExperiment(response);
      })));
    });

  });


  unittest.group("resource-ManagementFiltersResourceApi", () {
    unittest.test("method--delete", () {

      var mock = new HttpServerMock();
      api.ManagementFiltersResourceApi res = new api.AnalyticsApi(mock).management.filters;
      var arg_accountId = "foo";
      var arg_filterId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/filters/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 9), unittest.equals("/filters/"));
        pathOffset += 9;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_filterId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildFilter());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.delete(arg_accountId, arg_filterId).then(unittest.expectAsync(((api.Filter response) {
        checkFilter(response);
      })));
    });

    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementFiltersResourceApi res = new api.AnalyticsApi(mock).management.filters;
      var arg_accountId = "foo";
      var arg_filterId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/filters/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 9), unittest.equals("/filters/"));
        pathOffset += 9;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_filterId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildFilter());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_filterId).then(unittest.expectAsync(((api.Filter response) {
        checkFilter(response);
      })));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementFiltersResourceApi res = new api.AnalyticsApi(mock).management.filters;
      var arg_request = buildFilter();
      var arg_accountId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Filter.fromJson(json);
        checkFilter(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/filters", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 8), unittest.equals("/filters"));
        pathOffset += 8;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildFilter());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId).then(unittest.expectAsync(((api.Filter response) {
        checkFilter(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementFiltersResourceApi res = new api.AnalyticsApi(mock).management.filters;
      var arg_accountId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/filters", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 8), unittest.equals("/filters"));
        pathOffset += 8;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildFilters());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.Filters response) {
        checkFilters(response);
      })));
    });

    unittest.test("method--patch", () {

      var mock = new HttpServerMock();
      api.ManagementFiltersResourceApi res = new api.AnalyticsApi(mock).management.filters;
      var arg_request = buildFilter();
      var arg_accountId = "foo";
      var arg_filterId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Filter.fromJson(json);
        checkFilter(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/filters/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 9), unittest.equals("/filters/"));
        pathOffset += 9;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_filterId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildFilter());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.patch(arg_request, arg_accountId, arg_filterId).then(unittest.expectAsync(((api.Filter response) {
        checkFilter(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementFiltersResourceApi res = new api.AnalyticsApi(mock).management.filters;
      var arg_request = buildFilter();
      var arg_accountId = "foo";
      var arg_filterId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Filter.fromJson(json);
        checkFilter(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/filters/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 9), unittest.equals("/filters/"));
        pathOffset += 9;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_filterId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildFilter());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_filterId).then(unittest.expectAsync(((api.Filter response) {
        checkFilter(response);
      })));
    });

  });


  unittest.group("resource-ManagementGoalsResourceApi", () {
    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementGoalsResourceApi res = new api.AnalyticsApi(mock).management.goals;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_goalId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/goals/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 7), unittest.equals("/goals/"));
        pathOffset += 7;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_goalId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildGoal());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_webPropertyId, arg_profileId, arg_goalId).then(unittest.expectAsync(((api.Goal response) {
        checkGoal(response);
      })));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementGoalsResourceApi res = new api.AnalyticsApi(mock).management.goals;
      var arg_request = buildGoal();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Goal.fromJson(json);
        checkGoal(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/goals", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 6), unittest.equals("/goals"));
        pathOffset += 6;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildGoal());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId, arg_webPropertyId, arg_profileId).then(unittest.expectAsync(((api.Goal response) {
        checkGoal(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementGoalsResourceApi res = new api.AnalyticsApi(mock).management.goals;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/goals", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 6), unittest.equals("/goals"));
        pathOffset += 6;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildGoals());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, arg_profileId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.Goals response) {
        checkGoals(response);
      })));
    });

    unittest.test("method--patch", () {

      var mock = new HttpServerMock();
      api.ManagementGoalsResourceApi res = new api.AnalyticsApi(mock).management.goals;
      var arg_request = buildGoal();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_goalId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Goal.fromJson(json);
        checkGoal(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/goals/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 7), unittest.equals("/goals/"));
        pathOffset += 7;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_goalId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildGoal());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.patch(arg_request, arg_accountId, arg_webPropertyId, arg_profileId, arg_goalId).then(unittest.expectAsync(((api.Goal response) {
        checkGoal(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementGoalsResourceApi res = new api.AnalyticsApi(mock).management.goals;
      var arg_request = buildGoal();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_goalId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Goal.fromJson(json);
        checkGoal(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/goals/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 7), unittest.equals("/goals/"));
        pathOffset += 7;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_goalId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildGoal());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_webPropertyId, arg_profileId, arg_goalId).then(unittest.expectAsync(((api.Goal response) {
        checkGoal(response);
      })));
    });

  });


  unittest.group("resource-ManagementProfileFilterLinksResourceApi", () {
    unittest.test("method--delete", () {

      var mock = new HttpServerMock();
      api.ManagementProfileFilterLinksResourceApi res = new api.AnalyticsApi(mock).management.profileFilterLinks;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_linkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/profileFilterLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("/profileFilterLinks/"));
        pathOffset += 20;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_linkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = "";
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.delete(arg_accountId, arg_webPropertyId, arg_profileId, arg_linkId).then(unittest.expectAsync((_) {}));
    });

    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementProfileFilterLinksResourceApi res = new api.AnalyticsApi(mock).management.profileFilterLinks;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_linkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/profileFilterLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("/profileFilterLinks/"));
        pathOffset += 20;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_linkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildProfileFilterLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_webPropertyId, arg_profileId, arg_linkId).then(unittest.expectAsync(((api.ProfileFilterLink response) {
        checkProfileFilterLink(response);
      })));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementProfileFilterLinksResourceApi res = new api.AnalyticsApi(mock).management.profileFilterLinks;
      var arg_request = buildProfileFilterLink();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.ProfileFilterLink.fromJson(json);
        checkProfileFilterLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/profileFilterLinks", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 19), unittest.equals("/profileFilterLinks"));
        pathOffset += 19;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildProfileFilterLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId, arg_webPropertyId, arg_profileId).then(unittest.expectAsync(((api.ProfileFilterLink response) {
        checkProfileFilterLink(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementProfileFilterLinksResourceApi res = new api.AnalyticsApi(mock).management.profileFilterLinks;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/profileFilterLinks", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 19), unittest.equals("/profileFilterLinks"));
        pathOffset += 19;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildProfileFilterLinks());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, arg_profileId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.ProfileFilterLinks response) {
        checkProfileFilterLinks(response);
      })));
    });

    unittest.test("method--patch", () {

      var mock = new HttpServerMock();
      api.ManagementProfileFilterLinksResourceApi res = new api.AnalyticsApi(mock).management.profileFilterLinks;
      var arg_request = buildProfileFilterLink();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_linkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.ProfileFilterLink.fromJson(json);
        checkProfileFilterLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/profileFilterLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("/profileFilterLinks/"));
        pathOffset += 20;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_linkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildProfileFilterLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.patch(arg_request, arg_accountId, arg_webPropertyId, arg_profileId, arg_linkId).then(unittest.expectAsync(((api.ProfileFilterLink response) {
        checkProfileFilterLink(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementProfileFilterLinksResourceApi res = new api.AnalyticsApi(mock).management.profileFilterLinks;
      var arg_request = buildProfileFilterLink();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_linkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.ProfileFilterLink.fromJson(json);
        checkProfileFilterLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/profileFilterLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("/profileFilterLinks/"));
        pathOffset += 20;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_linkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildProfileFilterLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_webPropertyId, arg_profileId, arg_linkId).then(unittest.expectAsync(((api.ProfileFilterLink response) {
        checkProfileFilterLink(response);
      })));
    });

  });


  unittest.group("resource-ManagementProfileUserLinksResourceApi", () {
    unittest.test("method--delete", () {

      var mock = new HttpServerMock();
      api.ManagementProfileUserLinksResourceApi res = new api.AnalyticsApi(mock).management.profileUserLinks;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_linkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/entityUserLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/entityUserLinks/"));
        pathOffset += 17;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_linkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = "";
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.delete(arg_accountId, arg_webPropertyId, arg_profileId, arg_linkId).then(unittest.expectAsync((_) {}));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementProfileUserLinksResourceApi res = new api.AnalyticsApi(mock).management.profileUserLinks;
      var arg_request = buildEntityUserLink();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.EntityUserLink.fromJson(json);
        checkEntityUserLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/entityUserLinks", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 16), unittest.equals("/entityUserLinks"));
        pathOffset += 16;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityUserLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId, arg_webPropertyId, arg_profileId).then(unittest.expectAsync(((api.EntityUserLink response) {
        checkEntityUserLink(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementProfileUserLinksResourceApi res = new api.AnalyticsApi(mock).management.profileUserLinks;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/entityUserLinks", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 16), unittest.equals("/entityUserLinks"));
        pathOffset += 16;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityUserLinks());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, arg_profileId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.EntityUserLinks response) {
        checkEntityUserLinks(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementProfileUserLinksResourceApi res = new api.AnalyticsApi(mock).management.profileUserLinks;
      var arg_request = buildEntityUserLink();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_linkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.EntityUserLink.fromJson(json);
        checkEntityUserLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/entityUserLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/entityUserLinks/"));
        pathOffset += 17;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_linkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityUserLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_webPropertyId, arg_profileId, arg_linkId).then(unittest.expectAsync(((api.EntityUserLink response) {
        checkEntityUserLink(response);
      })));
    });

  });


  unittest.group("resource-ManagementProfilesResourceApi", () {
    unittest.test("method--delete", () {

      var mock = new HttpServerMock();
      api.ManagementProfilesResourceApi res = new api.AnalyticsApi(mock).management.profiles;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = "";
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.delete(arg_accountId, arg_webPropertyId, arg_profileId).then(unittest.expectAsync((_) {}));
    });

    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementProfilesResourceApi res = new api.AnalyticsApi(mock).management.profiles;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildProfile());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_webPropertyId, arg_profileId).then(unittest.expectAsync(((api.Profile response) {
        checkProfile(response);
      })));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementProfilesResourceApi res = new api.AnalyticsApi(mock).management.profiles;
      var arg_request = buildProfile();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Profile.fromJson(json);
        checkProfile(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 9), unittest.equals("/profiles"));
        pathOffset += 9;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildProfile());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId, arg_webPropertyId).then(unittest.expectAsync(((api.Profile response) {
        checkProfile(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementProfilesResourceApi res = new api.AnalyticsApi(mock).management.profiles;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 9), unittest.equals("/profiles"));
        pathOffset += 9;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildProfiles());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.Profiles response) {
        checkProfiles(response);
      })));
    });

    unittest.test("method--patch", () {

      var mock = new HttpServerMock();
      api.ManagementProfilesResourceApi res = new api.AnalyticsApi(mock).management.profiles;
      var arg_request = buildProfile();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Profile.fromJson(json);
        checkProfile(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildProfile());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.patch(arg_request, arg_accountId, arg_webPropertyId, arg_profileId).then(unittest.expectAsync(((api.Profile response) {
        checkProfile(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementProfilesResourceApi res = new api.AnalyticsApi(mock).management.profiles;
      var arg_request = buildProfile();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Profile.fromJson(json);
        checkProfile(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildProfile());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_webPropertyId, arg_profileId).then(unittest.expectAsync(((api.Profile response) {
        checkProfile(response);
      })));
    });

  });


  unittest.group("resource-ManagementSegmentsResourceApi", () {
    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementSegmentsResourceApi res = new api.AnalyticsApi(mock).management.segments;
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 19), unittest.equals("management/segments"));
        pathOffset += 19;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildSegments());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.Segments response) {
        checkSegments(response);
      })));
    });

  });


  unittest.group("resource-ManagementUnsampledReportsResourceApi", () {
    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementUnsampledReportsResourceApi res = new api.AnalyticsApi(mock).management.unsampledReports;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_unsampledReportId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/unsampledReports/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 18), unittest.equals("/unsampledReports/"));
        pathOffset += 18;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_unsampledReportId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildUnsampledReport());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_webPropertyId, arg_profileId, arg_unsampledReportId).then(unittest.expectAsync(((api.UnsampledReport response) {
        checkUnsampledReport(response);
      })));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementUnsampledReportsResourceApi res = new api.AnalyticsApi(mock).management.unsampledReports;
      var arg_request = buildUnsampledReport();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.UnsampledReport.fromJson(json);
        checkUnsampledReport(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/unsampledReports", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/unsampledReports"));
        pathOffset += 17;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildUnsampledReport());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId, arg_webPropertyId, arg_profileId).then(unittest.expectAsync(((api.UnsampledReport response) {
        checkUnsampledReport(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementUnsampledReportsResourceApi res = new api.AnalyticsApi(mock).management.unsampledReports;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_profileId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/profiles/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 10), unittest.equals("/profiles/"));
        pathOffset += 10;
        index = path.indexOf("/unsampledReports", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_profileId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/unsampledReports"));
        pathOffset += 17;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildUnsampledReports());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, arg_profileId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.UnsampledReports response) {
        checkUnsampledReports(response);
      })));
    });

  });


  unittest.group("resource-ManagementUploadsResourceApi", () {
    unittest.test("method--deleteUploadData", () {

      var mock = new HttpServerMock();
      api.ManagementUploadsResourceApi res = new api.AnalyticsApi(mock).management.uploads;
      var arg_request = buildAnalyticsDataimportDeleteUploadDataRequest();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_customDataSourceId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.AnalyticsDataimportDeleteUploadDataRequest.fromJson(json);
        checkAnalyticsDataimportDeleteUploadDataRequest(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customDataSources/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 19), unittest.equals("/customDataSources/"));
        pathOffset += 19;
        index = path.indexOf("/deleteUploadData", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_customDataSourceId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/deleteUploadData"));
        pathOffset += 17;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = "";
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.deleteUploadData(arg_request, arg_accountId, arg_webPropertyId, arg_customDataSourceId).then(unittest.expectAsync((_) {}));
    });

    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementUploadsResourceApi res = new api.AnalyticsApi(mock).management.uploads;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_customDataSourceId = "foo";
      var arg_uploadId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customDataSources/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 19), unittest.equals("/customDataSources/"));
        pathOffset += 19;
        index = path.indexOf("/uploads/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_customDataSourceId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 9), unittest.equals("/uploads/"));
        pathOffset += 9;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_uploadId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildUpload());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_webPropertyId, arg_customDataSourceId, arg_uploadId).then(unittest.expectAsync(((api.Upload response) {
        checkUpload(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementUploadsResourceApi res = new api.AnalyticsApi(mock).management.uploads;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_customDataSourceId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customDataSources/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 19), unittest.equals("/customDataSources/"));
        pathOffset += 19;
        index = path.indexOf("/uploads", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_customDataSourceId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 8), unittest.equals("/uploads"));
        pathOffset += 8;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildUploads());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, arg_customDataSourceId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.Uploads response) {
        checkUploads(response);
      })));
    });

    unittest.test("method--uploadData", () {
      // TODO: Implement tests for media upload;
      // TODO: Implement tests for media download;

      var mock = new HttpServerMock();
      api.ManagementUploadsResourceApi res = new api.AnalyticsApi(mock).management.uploads;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_customDataSourceId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/customDataSources/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 19), unittest.equals("/customDataSources/"));
        pathOffset += 19;
        index = path.indexOf("/uploads", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_customDataSourceId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 8), unittest.equals("/uploads"));
        pathOffset += 8;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildUpload());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.uploadData(arg_accountId, arg_webPropertyId, arg_customDataSourceId).then(unittest.expectAsync(((api.Upload response) {
        checkUpload(response);
      })));
    });

  });


  unittest.group("resource-ManagementWebPropertyAdWordsLinksResourceApi", () {
    unittest.test("method--delete", () {

      var mock = new HttpServerMock();
      api.ManagementWebPropertyAdWordsLinksResourceApi res = new api.AnalyticsApi(mock).management.webPropertyAdWordsLinks;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_webPropertyAdWordsLinkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/entityAdWordsLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("/entityAdWordsLinks/"));
        pathOffset += 20;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyAdWordsLinkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = "";
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.delete(arg_accountId, arg_webPropertyId, arg_webPropertyAdWordsLinkId).then(unittest.expectAsync((_) {}));
    });

    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementWebPropertyAdWordsLinksResourceApi res = new api.AnalyticsApi(mock).management.webPropertyAdWordsLinks;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_webPropertyAdWordsLinkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/entityAdWordsLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("/entityAdWordsLinks/"));
        pathOffset += 20;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyAdWordsLinkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityAdWordsLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_webPropertyId, arg_webPropertyAdWordsLinkId).then(unittest.expectAsync(((api.EntityAdWordsLink response) {
        checkEntityAdWordsLink(response);
      })));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementWebPropertyAdWordsLinksResourceApi res = new api.AnalyticsApi(mock).management.webPropertyAdWordsLinks;
      var arg_request = buildEntityAdWordsLink();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.EntityAdWordsLink.fromJson(json);
        checkEntityAdWordsLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/entityAdWordsLinks", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 19), unittest.equals("/entityAdWordsLinks"));
        pathOffset += 19;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityAdWordsLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId, arg_webPropertyId).then(unittest.expectAsync(((api.EntityAdWordsLink response) {
        checkEntityAdWordsLink(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementWebPropertyAdWordsLinksResourceApi res = new api.AnalyticsApi(mock).management.webPropertyAdWordsLinks;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/entityAdWordsLinks", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 19), unittest.equals("/entityAdWordsLinks"));
        pathOffset += 19;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityAdWordsLinks());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.EntityAdWordsLinks response) {
        checkEntityAdWordsLinks(response);
      })));
    });

    unittest.test("method--patch", () {

      var mock = new HttpServerMock();
      api.ManagementWebPropertyAdWordsLinksResourceApi res = new api.AnalyticsApi(mock).management.webPropertyAdWordsLinks;
      var arg_request = buildEntityAdWordsLink();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_webPropertyAdWordsLinkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.EntityAdWordsLink.fromJson(json);
        checkEntityAdWordsLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/entityAdWordsLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("/entityAdWordsLinks/"));
        pathOffset += 20;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyAdWordsLinkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityAdWordsLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.patch(arg_request, arg_accountId, arg_webPropertyId, arg_webPropertyAdWordsLinkId).then(unittest.expectAsync(((api.EntityAdWordsLink response) {
        checkEntityAdWordsLink(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementWebPropertyAdWordsLinksResourceApi res = new api.AnalyticsApi(mock).management.webPropertyAdWordsLinks;
      var arg_request = buildEntityAdWordsLink();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_webPropertyAdWordsLinkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.EntityAdWordsLink.fromJson(json);
        checkEntityAdWordsLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/entityAdWordsLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("/entityAdWordsLinks/"));
        pathOffset += 20;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyAdWordsLinkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityAdWordsLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_webPropertyId, arg_webPropertyAdWordsLinkId).then(unittest.expectAsync(((api.EntityAdWordsLink response) {
        checkEntityAdWordsLink(response);
      })));
    });

  });


  unittest.group("resource-ManagementWebpropertiesResourceApi", () {
    unittest.test("method--get", () {

      var mock = new HttpServerMock();
      api.ManagementWebpropertiesResourceApi res = new api.AnalyticsApi(mock).management.webproperties;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildWebproperty());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.get(arg_accountId, arg_webPropertyId).then(unittest.expectAsync(((api.Webproperty response) {
        checkWebproperty(response);
      })));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementWebpropertiesResourceApi res = new api.AnalyticsApi(mock).management.webproperties;
      var arg_request = buildWebproperty();
      var arg_accountId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Webproperty.fromJson(json);
        checkWebproperty(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 14), unittest.equals("/webproperties"));
        pathOffset += 14;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildWebproperty());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId).then(unittest.expectAsync(((api.Webproperty response) {
        checkWebproperty(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementWebpropertiesResourceApi res = new api.AnalyticsApi(mock).management.webproperties;
      var arg_accountId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 14), unittest.equals("/webproperties"));
        pathOffset += 14;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildWebproperties());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.Webproperties response) {
        checkWebproperties(response);
      })));
    });

    unittest.test("method--patch", () {

      var mock = new HttpServerMock();
      api.ManagementWebpropertiesResourceApi res = new api.AnalyticsApi(mock).management.webproperties;
      var arg_request = buildWebproperty();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Webproperty.fromJson(json);
        checkWebproperty(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildWebproperty());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.patch(arg_request, arg_accountId, arg_webPropertyId).then(unittest.expectAsync(((api.Webproperty response) {
        checkWebproperty(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementWebpropertiesResourceApi res = new api.AnalyticsApi(mock).management.webproperties;
      var arg_request = buildWebproperty();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.Webproperty.fromJson(json);
        checkWebproperty(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildWebproperty());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_webPropertyId).then(unittest.expectAsync(((api.Webproperty response) {
        checkWebproperty(response);
      })));
    });

  });


  unittest.group("resource-ManagementWebpropertyUserLinksResourceApi", () {
    unittest.test("method--delete", () {

      var mock = new HttpServerMock();
      api.ManagementWebpropertyUserLinksResourceApi res = new api.AnalyticsApi(mock).management.webpropertyUserLinks;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_linkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/entityUserLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/entityUserLinks/"));
        pathOffset += 17;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_linkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = "";
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.delete(arg_accountId, arg_webPropertyId, arg_linkId).then(unittest.expectAsync((_) {}));
    });

    unittest.test("method--insert", () {

      var mock = new HttpServerMock();
      api.ManagementWebpropertyUserLinksResourceApi res = new api.AnalyticsApi(mock).management.webpropertyUserLinks;
      var arg_request = buildEntityUserLink();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.EntityUserLink.fromJson(json);
        checkEntityUserLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/entityUserLinks", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 16), unittest.equals("/entityUserLinks"));
        pathOffset += 16;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityUserLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.insert(arg_request, arg_accountId, arg_webPropertyId).then(unittest.expectAsync(((api.EntityUserLink response) {
        checkEntityUserLink(response);
      })));
    });

    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.ManagementWebpropertyUserLinksResourceApi res = new api.AnalyticsApi(mock).management.webpropertyUserLinks;
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_max_results = 42;
      var arg_start_index = 42;
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/entityUserLinks", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 16), unittest.equals("/entityUserLinks"));
        pathOffset += 16;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }
        unittest.expect(core.int.parse(queryMap["max-results"].first), unittest.equals(arg_max_results));
        unittest.expect(core.int.parse(queryMap["start-index"].first), unittest.equals(arg_start_index));


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityUserLinks());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_accountId, arg_webPropertyId, max_results: arg_max_results, start_index: arg_start_index).then(unittest.expectAsync(((api.EntityUserLinks response) {
        checkEntityUserLinks(response);
      })));
    });

    unittest.test("method--update", () {

      var mock = new HttpServerMock();
      api.ManagementWebpropertyUserLinksResourceApi res = new api.AnalyticsApi(mock).management.webpropertyUserLinks;
      var arg_request = buildEntityUserLink();
      var arg_accountId = "foo";
      var arg_webPropertyId = "foo";
      var arg_linkId = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.EntityUserLink.fromJson(json);
        checkEntityUserLink(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 20), unittest.equals("management/accounts/"));
        pathOffset += 20;
        index = path.indexOf("/webproperties/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_accountId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 15), unittest.equals("/webproperties/"));
        pathOffset += 15;
        index = path.indexOf("/entityUserLinks/", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_webPropertyId"));
        unittest.expect(path.substring(pathOffset, pathOffset + 17), unittest.equals("/entityUserLinks/"));
        pathOffset += 17;
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset));
        pathOffset = path.length;
        unittest.expect(subPart, unittest.equals("$arg_linkId"));

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildEntityUserLink());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.update(arg_request, arg_accountId, arg_webPropertyId, arg_linkId).then(unittest.expectAsync(((api.EntityUserLink response) {
        checkEntityUserLink(response);
      })));
    });

  });


  unittest.group("resource-MetadataColumnsResourceApi", () {
    unittest.test("method--list", () {

      var mock = new HttpServerMock();
      api.MetadataColumnsResourceApi res = new api.AnalyticsApi(mock).metadata.columns;
      var arg_reportType = "foo";
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 9), unittest.equals("metadata/"));
        pathOffset += 9;
        index = path.indexOf("/columns", pathOffset);
        unittest.expect(index >= 0, unittest.isTrue);
        subPart = core.Uri.decodeQueryComponent(path.substring(pathOffset, index));
        pathOffset = index;
        unittest.expect(subPart, unittest.equals("$arg_reportType"));
        unittest.expect(path.substring(pathOffset, pathOffset + 8), unittest.equals("/columns"));
        pathOffset += 8;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildColumns());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.list(arg_reportType).then(unittest.expectAsync(((api.Columns response) {
        checkColumns(response);
      })));
    });

  });


  unittest.group("resource-ProvisioningResourceApi", () {
    unittest.test("method--createAccountTicket", () {

      var mock = new HttpServerMock();
      api.ProvisioningResourceApi res = new api.AnalyticsApi(mock).provisioning;
      var arg_request = buildAccountTicket();
      mock.register(unittest.expectAsync((http.BaseRequest req, json) {
        var obj = new api.AccountTicket.fromJson(json);
        checkAccountTicket(obj);

        var path = (req.url).path;
        var pathOffset = 0;
        var index;
        var subPart;
        unittest.expect(path.substring(pathOffset, pathOffset + 1), unittest.equals("/"));
        pathOffset += 1;
        unittest.expect(path.substring(pathOffset, pathOffset + 13), unittest.equals("analytics/v3/"));
        pathOffset += 13;
        unittest.expect(path.substring(pathOffset, pathOffset + 32), unittest.equals("provisioning/createAccountTicket"));
        pathOffset += 32;

        var query = (req.url).query;
        var queryOffset = 0;
        var queryMap = {};
        addQueryParam(n, v) => queryMap.putIfAbsent(n, () => []).add(v);
        parseBool(n) {
          if (n == "true") return true;
          if (n == "false") return false;
          if (n == null) return null;
          throw new core.ArgumentError("Invalid boolean: $n");
        }
        if (query.length > 0) {
          for (var part in query.split("&")) {
            var keyvalue = part.split("=");
            addQueryParam(core.Uri.decodeQueryComponent(keyvalue[0]), core.Uri.decodeQueryComponent(keyvalue[1]));
          }
        }


        var h = {
          "content-type" : "application/json; charset=utf-8",
        };
        var resp = convert.JSON.encode(buildAccountTicket());
        return new async.Future.value(stringResponse(200, h, resp));
      }), true);
      res.createAccountTicket(arg_request).then(unittest.expectAsync(((api.AccountTicket response) {
        checkAccountTicket(response);
      })));
    });

  });


}
