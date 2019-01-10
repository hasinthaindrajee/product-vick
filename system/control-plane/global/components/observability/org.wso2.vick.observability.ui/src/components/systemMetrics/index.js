/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import ControlPlane from "./ControlPlane";
import Node from "./Node";
import NotFound from "../common/error/NotFound";
import Pod from "./Pod";
import PropTypes from "prop-types";
import React from "react";
import {Route, Switch, withRouter} from "react-router-dom";

const SystemMetrics = ({match}) => (
    <Switch>
        <Route exact path={`${match.path}/control-plane`} component={ControlPlane}/>
        <Route exact path={`${match.path}/node-usage`} component={Node}/>
        <Route exact path={`${match.path}/pod-usage`} component={Pod}/>
        <Route path={`${match.url}/*`} component={NotFound}/>
    </Switch>
);

SystemMetrics.propTypes = {
    match: PropTypes.object.isRequired,
    location: PropTypes.shape({
        state: PropTypes.object
    }).isRequired
};

export default withRouter(SystemMetrics);
